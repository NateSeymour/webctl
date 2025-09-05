#include <unordered_map>
#include <string>
#include <variant>
#include <optional>
#include <ranges>
#include <iostream>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/dispatch.hpp>
#include <boost/asio/strand.hpp>
#include <boost/config.hpp>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
using tcp = boost::asio::ip::tcp;

template<class... Ts>
struct overloads : Ts... { using Ts::operator()...; };

using Response = http::message_generator;
using Request = http::request<http::string_body>;

struct Node
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

using Handler = std::variant<Node, Middleware>;

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
                tree = tree = &tree->children[std::string{part.begin(), part.end()}];
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
            auto const &node = std::get<Node>(handler);

            return (path == node.path && req.method() == node.method);
        });

        if (it != tree->handlers.end())
        {
            return std::get<Node>(*it).handler_function(req);
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
            std::string path = std::visit(overloads{
                [](Node const &node) {
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

RestProvider WebCtlRestProvider{
    Middleware{ "/", [](Request &req) -> std::optional<Response> {
        std::cout << "[Server] Received request to " << req.target() << std::endl;
        return std::nullopt;
    }},

    Middleware{ "/", [](Request &req) -> std::optional<Response> {
        /* PERFORM AUTHENTICATION */
        return std::nullopt;
    }},

    Node{ http::verb::get, "/info", [](Request const &req) -> Response {
        http::response<http::string_body> res{http::status::ok, req.version()};
        res.body() = "v0.0.1";

        return res;
    }},
};

class Session : public std::enable_shared_from_this<Session>
{
    beast::tcp_stream stream_;
    beast::flat_buffer buffer_;
    http::request<http::string_body> req_;

    void Close()
    {
        beast::error_code ec;
        this->stream_.socket().shutdown(tcp::socket::shutdown_send, ec);
    }

    void OnWrite(beast::error_code ec, std::size_t bytes)
    {
        this->Close();
    }

    void OnRead(beast::error_code ec, std::size_t bytes)
    {
        if (ec == http::error::end_of_stream)
        {
            this->Close();
        }

        if (ec)
        {
            throw std::runtime_error("HTTP read error!");
        }

        // Send Response
        auto res = WebCtlRestProvider.RespondTo(this->req_);
        beast::async_write(this->stream_, std::move(res), beast::bind_front_handler(&Session::OnWrite, this->shared_from_this()));
    }

    void Read()
    {
        this->req_ = {};
        this->stream_.expires_after(std::chrono::seconds(30));
        http::async_read(this->stream_, this->buffer_, this->req_, beast::bind_front_handler(&Session::OnRead, this->shared_from_this()));
    }

public:
    void Run()
    {
        net::dispatch(this->stream_.get_executor(), beast::bind_front_handler(&Session::Read, this->shared_from_this()));
    }

    Session(tcp::socket &&socket) : stream_(std::move(socket)) {}
};

class Server : public std::enable_shared_from_this<Server>
{
    net::io_context &ioc_;
    tcp::acceptor acceptor_;

    net::ip::address addr_ = net::ip::make_address("0.0.0.0");
    unsigned short port_ = 6969;

    void OnAccept(beast::error_code ec, tcp::socket socket)
    {
        if (ec)
        {
            throw std::runtime_error("Failed to accept!");
        }

        auto session = std::make_shared<Session>(std::move(socket));
        session->Run();

        this->Accept();
    }

    void Accept()
    {
        this->acceptor_.async_accept(net::make_strand(this->ioc_), beast::bind_front_handler(&Server::OnAccept, this->shared_from_this()));
    }

public:
    void Run()
    {
        this->Accept();
        this->ioc_.run();
    }

    Server(net::io_context &ioc) : ioc_(ioc), acceptor_(net::make_strand(ioc))
    {
        beast::error_code ec;

        tcp::endpoint endpoint{this->addr_, this->port_};

        this->acceptor_.open(endpoint.protocol(), ec);
        if (ec)
        {
            throw std::runtime_error("Failed to open acceptor!");
        }

        this->acceptor_.set_option(net::socket_base::reuse_address(true));
        this->acceptor_.bind(endpoint, ec);
        if (ec)
        {
            throw std::runtime_error("Failed to bind acceptor!");
        }

        this->acceptor_.listen(net::socket_base::max_listen_connections, ec);
        if (ec)
        {
            throw std::runtime_error("Failed to listen to acceptor!");
        }
    }
};

int main()
{
    net::io_context ioc;

    auto server = std::make_shared<Server>(ioc);
    server->Run();

    return 0;
}