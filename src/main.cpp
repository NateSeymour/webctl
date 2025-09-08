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

namespace beast = boost::beast;
namespace http = beast::http;
namespace asio = boost::asio;
namespace ssl = asio::ssl;
namespace json = boost::json;
using tcp = asio::ip::tcp;

/*
 * Helper for std::visit provided by Andreas Fertig.
 * https://andreasfertig.blog/2023/07/visiting-a-stdvariant-safely/
 */
template<class...>
constexpr bool always_false_v = false;

template<class... Ts>
struct overload : Ts...
{
    using Ts::operator()...;

    template<typename T>
    constexpr void operator()(T) const
    {
        static_assert(always_false_v<T>, "Unsupported type");
    }
};

template<class... Ts>
overload(Ts...) -> overload<Ts...>;

class HTTPClient
{
    asio::io_context &ioc_;
    ssl::context ssl_ctx_;

public:
    asio::awaitable<http::response<http::dynamic_body>> RequestAsync(boost::url url)
    {
        auto executor = co_await asio::this_coro::executor;

        tcp::resolver resolver{executor};
        ssl::stream<beast::tcp_stream> stream{executor, this->ssl_ctx_};

        auto const resolved_host = co_await resolver.async_resolve(url.host(), "443");
        co_await beast::get_lowest_layer(stream).async_connect(resolved_host);

        co_await stream.async_handshake(ssl::stream_base::client);

        http::request<http::string_body> req{http::verb::get, url.path(), 11};
        req.set(http::field::host, url.host());
        req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

        co_await http::async_write(stream, req);

        beast::flat_buffer buffer;
        http::response<http::dynamic_body> res;
        co_await http::async_read(stream, buffer, res);

        auto [ec] = co_await stream.async_shutdown(asio::as_tuple);
        if(ec != ssl::error::stream_truncated)
        {
            throw beast::system_error{ec};
        }

        co_return res;
    }

    HTTPClient(asio::io_context &ioc, std::string_view ca_certs) : ioc_(ioc), ssl_ctx_(ssl::context::tlsv12_client)
    {
        std::cout << "[Client] Initializing..." << std::endl;

        this->ssl_ctx_.set_verify_mode(ssl::verify_peer);
        this->ssl_ctx_.add_certificate_authority(asio::buffer(ca_certs.data(), ca_certs.size()));
    }
};

struct JWKS
{
    std::unordered_map<std::string, json::value> keys;

    [[nodiscard]] static std::optional<JWKS> FromJson(json::value raw)
    {
        JWKS jwks;

        auto &keys = raw.as_object()["keys"];
        for (auto &key : keys.as_array())
        {
            auto &kid = key.as_object()["kid"].as_string();

            jwks.keys[std::string{kid}] = key;
        }

        return std::move(jwks);
    }
};

class JWKSProvider
{
    asio::io_context &ioc_;
    HTTPClient &http_client_;

    JWKS jwks_;
    std::mutex m_jwks_;

    asio::awaitable<void> FetchJWKS()
    {
        while (true)
        {
            std::cout << "[JWKSProvider] Fetching latest JWKS..." << std::endl;
            auto res = co_await this->http_client_.RequestAsync(boost::url{"https://cognito-idp.us-east-1.amazonaws.com/us-east-1_zLcMyB1HE/.well-known/jwks.json"});

            json::value jwks = json::parse(beast::buffers_to_string(res.body().data()));

            {
                std::lock_guard lk(this->m_jwks_);

                this->jwks_ = JWKS::FromJson(jwks).value();

                std::cout << "[JWKSProvider] Fetched latest JWKS. " << this->jwks_.keys.size() << " keys loaded:" << std::endl;
                for (auto const &[id, key] : this->jwks_.keys)
                {
                    std::cout << "[JWKSProvider] - " << id << std::endl;
                }
            }

            co_await asio::steady_timer{this->ioc_, std::chrono::minutes(10)}.async_wait();
        }
    }

public:
    JWKSProvider(asio::io_context &ioc, HTTPClient &http_client) : ioc_(ioc), http_client_(http_client)
    {
        std::cout << "[JWKSProvider] Initializing..." << std::endl;

        asio::co_spawn(this->ioc_, this->FetchJWKS(), asio::detached);
    }
};

using Response = http::message_generator;
using Request = http::request<http::string_body>;

struct Route
{
    using HandlerFunctionType = Response(*)(Request const&);

    http::verb method;
    char const *path;
    HandlerFunctionType handler_function;
};

struct Middleware
{
    using MiddlewareFunctionType = std::optional<Response>(*)(Request&);

    char const *path;
    MiddlewareFunctionType middleware_function;
};

using Handler = std::variant<Route, Middleware>;
using RestDescription = std::initializer_list<Handler>;

struct HandlerTree
{
    std::vector<Handler> handlers;
    std::unordered_map<std::string, HandlerTree> children;
};

class RestProvider
{
    HandlerTree handlers_;

public:
    [[nodiscard]] Response RespondTo(Request &req)
    {
        auto path = req.target();

        HandlerTree *tree = &this->handlers_;
        for (auto const part : std::views::split(path, std::string_view{"/"}))
        {
            if (!part.empty())
            {
                tree = &tree->children[std::string{part.begin(), part.end()}];
            }

            for (auto const &handler : tree->handlers)
            {
                if (std::holds_alternative<Middleware>(handler))
                {
                    auto middleware = std::get<Middleware>(handler);
                    auto res = middleware.middleware_function(req);

                    if (res)
                    {
                        return std::move(res.value());
                    }
                }
            }
        }

        auto const it = std::ranges::find_if(tree->handlers, [&](Handler &handler) {
            if (std::holds_alternative<Middleware>(handler)) return false;
            auto const &node = std::get<Route>(handler);

            return (path == node.path && req.method() == node.method);
        });

        if (it != tree->handlers.end())
        {
            return std::get<Route>(*it).handler_function(req);
        }

        auto res = http::response<http::string_body>{http::status::not_found, req.version()};
        res.body() = "404 Not Found";
        return res;
    }

    /**
     *
     * @param description Description of REST routes to build Provider from.
     */
    RestProvider(RestDescription const &description)
    {
        for (auto const &handler : description)
        {
            std::string path = std::visit(overload{
                [](Route const &node) {
                    return node.path;
                },
                [](Middleware const &middleware) {
                    return middleware.path;
                }
            }, handler);

            HandlerTree *tree = &this->handlers_;
            for (auto const part : std::views::split(path.substr(1), std::string_view{"/"}))
            {
                if (part.empty()) continue;

                tree = &tree->children[std::string{part.begin(), part.end()}];
            }

            tree->handlers.push_back(handler);
        }
    }
};

class Server
{
    asio::io_context &ioc_;

    RestProvider &rest_provider_;

    asio::ip::address addr_ = asio::ip::make_address("0.0.0.0");
    unsigned short port_ = 6969;

    tcp::acceptor acceptor_;
    tcp::endpoint endpoint_{addr_, port_};

    asio::awaitable<void> Session(beast::tcp_stream stream)
    {
        beast::flat_buffer buffer;
        http::request<http::string_body> req{};

        stream.expires_after(std::chrono::seconds(30));
        co_await http::async_read(stream, buffer, req);

        auto res = this->rest_provider_.RespondTo(req);

        co_await beast::async_write(stream, std::move(res));

        stream.socket().shutdown(tcp::socket::shutdown_send);
    }

    asio::awaitable<void> Listen()
    {
        beast::error_code ec;

        this->acceptor_.open(this->endpoint_.protocol(), ec);
        if (ec)
        {
            throw std::runtime_error("Failed to open acceptor!");
        }

        this->acceptor_.set_option(asio::socket_base::reuse_address(true));
        this->acceptor_.bind(this->endpoint_, ec);
        if (ec)
        {
            throw std::runtime_error("Failed to bind acceptor!");
        }

        this->acceptor_.listen(asio::socket_base::max_listen_connections, ec);
        if (ec)
        {
            throw std::runtime_error("Failed to listen to acceptor!");
        }

        auto executor = co_await asio::this_coro::executor;

        while (true)
        {
            beast::tcp_stream stream{co_await this->acceptor_.async_accept()};
            asio::co_spawn(executor, this->Session(std::move(stream)), [](std::exception_ptr e) {
                if (e)
                {
                    std::rethrow_exception(e);
                }
            });
        }
    }

public:
    Server(asio::io_context &ioc, RestProvider &rest_provider) : ioc_(ioc), acceptor_(asio::make_strand(ioc)), rest_provider_(rest_provider)
    {
        std::cout << "[Server] Initializing..." << std::endl;

        asio::co_spawn(this->ioc_, this->Listen(), [](std::exception_ptr e) {
            if (e)
            {
                std::rethrow_exception(e);
            }
        });
    }
};

RestProvider web_ctl_rest_provider{
    // Request Logging
    Middleware{ "/", [](Request &req) -> std::optional<Response> {
        std::cout << "[Server] Received request to " << req.target() << std::endl;
        return std::nullopt;
    }},

    // Authentication
    Middleware{ "/", [](Request &req) -> std::optional<Response> {
        auto res_unauthorized = http::response<http::empty_body>{http::status::unauthorized, req.version()};

        auto auth_header = req.find(http::field::authorization);
        if (auth_header == req.end())
        {
            return res_unauthorized;
        }

        auto token = auth_header->value();

        return std::nullopt;
    }},

    // Routes
    Route{ http::verb::get, "/info", [](Request const &req) -> Response {
        http::response<http::string_body> res{http::status::ok, req.version()};
        res.body() = "v0.0.1";

        return res;
    }},
};

int main(int argc, char const **argv)
{
    // 0. Read and Initialize Config
    // Load in ca certs
    std::ifstream ca_certs{argv[1]};
    std::string ca_string{std::istreambuf_iterator<char>{ca_certs}, {}};

    // Setup asio context
    asio::io_context ioc;

    HTTPClient client{ioc, ca_string};
    JWKSProvider jwks_provider{ioc, client};
    Server server{ioc, web_ctl_rest_provider};

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