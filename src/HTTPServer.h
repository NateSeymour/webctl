#ifndef HTTP_SERVER_H
#define HTTP_SERVER_H

#include <boost/asio.hpp>
#include <boost/beast.hpp>

namespace webctl
{
    namespace asio = boost::asio;
    namespace beast = boost::beast;
    namespace http = beast::http;
    using tcp = asio::ip::tcp;

    class HTTPServer
    {
        using HandlerType = std::function<http::response<http::string_body>(http::request<http::string_body> const &)>;

        asio::io_context &ioc_;

        HandlerType request_handler_;

        asio::ip::address addr_ = asio::ip::make_address("0.0.0.0");
        unsigned short port_ = 6969;

        tcp::acceptor acceptor_;
        tcp::endpoint endpoint_{addr_, port_};

        asio::awaitable<void> Session(beast::tcp_stream stream);

        asio::awaitable<void> Listen();

    public:
        HTTPServer(asio::io_context &ioc, HandlerType handler);
    };
}

#endif