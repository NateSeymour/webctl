#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

namespace webctl
{
    template<typename RestContextType>
    class HTTPServer
    {
        asio::io_context &ioc_;

        RestContextType &rest_ctx_;
        RestProvider<RestContextType> &rest_provider_;

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

            auto res = this->rest_provider_.Handle(this->rest_ctx_, req);

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
        Server(asio::io_context &ioc, RestProvider<RestContextType> &rest_provider, RestContextType &rest_ctx) : ioc_(ioc), acceptor_(asio::make_strand(ioc)), rest_provider_(rest_provider), rest_ctx_(rest_ctx)
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
}

#endif