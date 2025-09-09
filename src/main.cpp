#include <fstream>
#include <iostream>
#include <optional>
#include <thread>
#include <sdbus-c++/sdbus-c++.h>
#include <boost/beast.hpp>
#include <boost/json.hpp>
#include <boost/asio.hpp>
#include "HTTPClient.h"
#include "JwksProvider.h"
#include "RestProvider.h"
#include "HTTPServer.h"
#include "sdbus_json.h"

namespace http = boost::beast::http;
namespace json = boost::json;
namespace asio = boost::asio;

using namespace webctl;

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

        auto token = auth_header->value();
        auto jwt = JWT::FromToken(ctx.jwks_provider, token);

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
    HTTPServer server{ioc, web_ctl_rest_provider, webctl_ctx};

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