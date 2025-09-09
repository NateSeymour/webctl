#include <unordered_map>
#include <string>
#include <variant>
#include <optional>
#include <ranges>
#include <iostream>
#include <fstream>
#include <thread>
#include <vector>
#include <mutex>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/strand.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/use_future.hpp>
#include <boost/asio/as_tuple.hpp>
#include <boost/asio/detached.hpp>
#include <boost/url.hpp>
#include <boost/json.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/param_build.h>
#include <cppcodec/base64_url_unpadded.hpp>
#include <sdbus-c++/sdbus-c++.h>

namespace beast = boost::beast;
namespace http = beast::http;
namespace asio = boost::asio;
namespace ssl = asio::ssl;
namespace json = boost::json;
using tcp = asio::ip::tcp;
using base64 = cppcodec::base64_url_unpadded;

struct WebCtlContext
{
    JWKSProvider &jwks_provider;
};

RestProvider<WebCtlContext> web_ctl_rest_provider{
    // Request Logging
    Middleware<WebCtlContext>{ "/", [](WebCtlContext &ctx, Request &req) -> std::optional<Response> {
        std::cout << "[Server] Received request to " << req.target() << std::endl;
        return std::nullopt;
    }},

    // Authentication
    Middleware<WebCtlContext>{ "/", [](WebCtlContext &ctx, Request &req) -> std::optional<Response> {
        auto res_unauthorized = http::response<http::empty_body>{http::status::unauthorized, req.version()};

        // Check for Authorization header
        auto auth_header = req.find(http::field::authorization);
        if (auth_header == req.end())
        {
            return res_unauthorized;
        }

        // Parse token
        auto token = auth_header->value();

        std::vector<std::string> token_parts;
        token_parts.reserve(3);
        boost::split(token_parts, token, boost::is_any_of("."));

        if (token_parts.size() != 3)
        {
            return res_unauthorized;
        }

        auto header_raw = base64::decode(token_parts[0]);
        auto header = json::parse(std::string_view{(char*)header_raw.data(), header_raw.size()});

        auto claims_raw = base64::decode(token_parts[1]);
        auto claims = json::parse(std::string_view{(char*)claims_raw.data(), claims_raw.size()});

        std::string payload = token_parts[0] + "." + token_parts[1];
        auto sig = base64::decode(token_parts[2]);

        auto key = ctx.jwks_provider.GetKeyById(header.as_object()["kid"].as_string().data());
        if (!key)
        {
            return res_unauthorized;
        }

        // Build key
        EVP_PKEY_CTX *evp_ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
        EVP_PKEY *pkey = nullptr;

        std::string e_base64 = key.value().as_object()["e"].as_string().data();
        std::string n_base64 = key.value().as_object()["n"].as_string().data();

        auto e = base64::decode(e_base64);
        auto n = base64::decode(n_base64);

        OSSL_PARAM_BLD *param_bld = OSSL_PARAM_BLD_new();

        BIGNUM *e_bn = BN_bin2bn(e.data(), static_cast<int>(e.size()), nullptr);
        BIGNUM *n_bn = BN_bin2bn(n.data(), static_cast<int>(n.size()), nullptr);

        OSSL_PARAM_BLD_push_BN(param_bld, "n", n_bn);
        OSSL_PARAM_BLD_push_BN(param_bld, "e", e_bn);

        OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(param_bld);

        if (auto err = EVP_PKEY_fromdata_init(evp_ctx); err <= 0)
        {
            std::cerr << ERR_error_string(err, nullptr) << std::endl;
        }

        if (auto err = EVP_PKEY_fromdata(evp_ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params); err <= 0)
        {
            std::cerr << ERR_error_string(err, nullptr) << std::endl;
        }

        // Verify signature
        EVP_MD_CTX *md_ctx = EVP_MD_CTX_create();

        EVP_MD const *md = EVP_get_digestbyname("SHA256");
        if (!md)
        {
            EVP_MD_CTX_free(md_ctx);
            return res_unauthorized;
        }

        EVP_VerifyInit(md_ctx, md);

        EVP_VerifyUpdate(md_ctx, payload.c_str(), payload.size());
        int valid = EVP_VerifyFinal(md_ctx, sig.data(), sig.size(), pkey);

        EVP_PKEY_CTX_free(evp_ctx);
        EVP_PKEY_free(pkey);
        BN_free(e_bn);
        BN_free(n_bn);
        OSSL_PARAM_BLD_free(param_bld);
        OSSL_PARAM_free(params);
        EVP_MD_CTX_free(md_ctx);

        if (valid != 1)
        {
            return res_unauthorized;
        }

        return std::nullopt;
    }},

    // Routes
    Route<WebCtlContext>{ http::verb::get, "/info", [](WebCtlContext &ctx, Request const &req) -> Response {
        http::response<http::string_body> res{http::status::ok, req.version()};
        res.body() = "v0.0.1";

        return res;
    }},

    /*
     * POST /ctl
     * Body: JSON
     * { "method": string, "args": any }
     */
    Route<WebCtlContext>{ http::verb::post, "/systemd", [](WebCtlContext &ctx, Request const &req) -> Response {
        http::response<http::string_body> res{http::status::ok, req.version()};

        sdbus::ServiceName destination{"org.freedesktop.systemd1"};
        sdbus::ObjectPath object_path{"/org/freedesktop/systemd1"};

        auto proxy = sdbus::createProxy(std::move(destination), std::move(object_path));

        sdbus::InterfaceName interface_name{"org.freedesktop.systemd1.Manager"};

        sdbus::MethodName method_name{"ListUnits"};

        auto method = proxy->createMethodCall(interface_name, method_name);
        auto reply = proxy->callMethod(method);

        json::value reply_json;
        reply >> reply_json;

        res.body() = json::serialize(reply_json);

        return res;
    }},
};

int main(int argc, char const **argv)
{
    // 0. Read and Initialize Config
    // Load in ca certs
    std::ifstream ca_certs{"/etc/ssl/certs/ca-certificates.crt"};
    std::string ca_string{std::istreambuf_iterator<char>{ca_certs}, {}};

    // Setup asio context
    asio::io_context ioc;

    HTTPClient client{ioc, ca_string};
    JWKSProvider jwks_provider{ioc, client};

    WebCtlContext webctl_ctx{
        .jwks_provider = jwks_provider,
    };
    Server server{ioc, web_ctl_rest_provider, webctl_ctx};

    // Launch threads
    std::size_t thread_count = std::thread::hardware_concurrency();
    std::vector<std::thread> threads;
    threads.reserve(thread_count);
    for (std::size_t i = 0; i < thread_count; i++)
    {
        threads.emplace_back([&] {
            ioc.run();
        });
    }

    ioc.run();

    return 0;
}