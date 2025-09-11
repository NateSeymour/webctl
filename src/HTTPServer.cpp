#include "HTTPServer.h"
#include <iostream>
#include <boost/json.hpp>

namespace json = boost::json;

using namespace webctl;

asio::awaitable<void> HTTPServer::Session(beast::tcp_stream stream)
{
    beast::flat_buffer buffer;
    http::request<http::string_body> req{};

    stream.expires_after(std::chrono::seconds(30));
    co_await http::async_read(stream, buffer, req);

    http::response<http::string_body> res;

    try
    {
        res = this->request_handler_(req);
    }
    catch (std::exception &e)
    {
        res.result(http::status::internal_server_error);
        res.body() = json::serialize(json::object{
            {"error", "Internal Server Error"},
            {"message", e.what()},
        });
    }

    if (res.result() != http::status::ok)
    {
        std::cerr << "[Server] Handler generated following error response:" << std::endl;
        std::cerr << "[Server] " << res.body() << std::endl;
    }

    http::message_generator generator = std::move(res);
    co_await beast::async_write(stream, std::move(generator));

    stream.socket().shutdown(tcp::socket::shutdown_send);
}

asio::awaitable<void> HTTPServer::Listen()
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

HTTPServer::HTTPServer(asio::io_context &ioc, HandlerType handler) : ioc_(ioc), acceptor_(asio::make_strand(ioc)), request_handler_(handler)
{
    std::cout << "[Server] Initializing..." << std::endl;

    asio::co_spawn(this->ioc_, this->Listen(), [](std::exception_ptr e) {
        if (e)
        {
            std::rethrow_exception(e);
        }
    });
}
