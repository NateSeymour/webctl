#include <fstream>
#include <iostream>
#include <thread>
#include <functional>
#include <filesystem>
#include <boost/beast.hpp>
#include <boost/json.hpp>
#include <boost/asio.hpp>
#include <sdbus-c++/sdbus-c++.h>
#include <toml++/toml.hpp>
#include "HTTPClient.h"
#include "OIDCProvider.h"
#include "HTTPServer.h"
#include "sdbus_json.h"

namespace http = boost::beast::http;
namespace json = boost::json;
namespace asio = boost::asio;

using namespace webctl;

http::response<http::string_body> request_handler(OIDCProvider &oidc_provider, http::request<http::string_body> const &req)
{
    http::response<http::string_body> res{};
    std::error_code ec;

    // Check for Authorization header
    auto auth_header = req.find(http::field::authorization);
    if (auth_header == req.end())
    {
        res.result(http::status::unauthorized);
        res.body() = json::serialize(json::object{
            {"error", "Missing Authorization Header"},
        });
        return res;
    }

    auto token = auth_header->value();
    auto jwt = oidc_provider.ValidateToken(token);

    if (!jwt)
    {
        res.result(http::status::unauthorized);
        res.body() = json::serialize(json::object{
            {"error", "Invalid Authorization Token"},
            {"code", static_cast<int>(jwt.error())},
        });
        return res;
    }

    // Process Request
    boost::url endpoint{req.target()};
    auto service = endpoint.segments().front();

    json::value body = json::parse(req.body(), ec);
    if (ec)
    {
        res.result(http::status::bad_request);
        res.body() = json::serialize(json::object{
            {"error", "Malformed Request"},
            {"message", ec.message()},
        });
        return res;
    }

    sdbus::ServiceName destination{service};
    sdbus::ObjectPath object_path{body.as_object()["object"].as_string().c_str()};

    auto proxy = sdbus::createProxy(std::move(destination), std::move(object_path));

    sdbus::InterfaceName interface_name{body.as_object()["interface"].as_string().c_str()};

    sdbus::MethodName method_name{body.as_object()["method"].as_string().c_str()};

    auto method = proxy->createMethodCall(interface_name, method_name);
    auto reply = proxy->callMethod(method);

    json::value reply_json;
    reply >> reply_json;

    res.result(http::status::ok);
    res.body() = json::serialize(reply_json);

    return res;
}

struct WebctlConfig
{
    std::filesystem::path ca_cert_path = "/etc/ssl/certs/ca-certificates.crt";
    std::string oidc_authority;

    [[nodiscard]] static WebctlConfig LoadFromSystem()
    {
        WebctlConfig config{};

        std::filesystem::path const search_paths[] = {
            "/etc/webctl.toml",
            "/usr/local/etc/webctl.toml",
            "./webctl.toml",
        };

        for (auto const &path : search_paths)
        {
            try
            {
                toml::table table = toml::parse_file(path.c_str());

                auto webctl = table["webctl"];
                if (!webctl) continue;

                if (auto ca_cert_path = webctl["ca_cert_path"].value<std::string_view>(); ca_cert_path)
                {
                    config.ca_cert_path = ca_cert_path.value();
                }

                if (auto oidc_authority = webctl["oidc_authority"].value<std::string_view>(); oidc_authority)
                {
                    config.oidc_authority = oidc_authority.value();
                }

                std::cout << "[Config] Loaded config from " << path << std::endl;
            }
            catch (std::exception &e)
            {
                std::cerr << "[Config] Unable to load config from " << path << std::endl;
            }
        }

        return std::move(config);
    }
};

int main(int argc, char const **argv)
{
    auto config = WebctlConfig::LoadFromSystem();

    if (config.ca_cert_path.empty())
    {
        std::cerr << "[Main] Invalid path to CA Certificates" << std::endl;
        return 1;
    }

    if (config.oidc_authority.empty())
    {
        std::cerr << "[Main] Invalid OIDC Authority" << std::endl;
        return 1;
    }

    // Load in ca certs
    std::ifstream ca_certs{config.ca_cert_path};
    std::string ca_string{std::istreambuf_iterator<char>{ca_certs}, {}};

    // Setup asio context
    asio::io_context ioc;

    HTTPClient client{ioc, ca_string};
    OIDCProvider oidc_provider{ioc, client, boost::url{config.oidc_authority}};
    HTTPServer server{ioc, std::bind(request_handler, std::ref(oidc_provider), std::placeholders::_1)};

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