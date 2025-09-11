#ifndef HTTP_CLIENT_H
#define HTTP_CLIENT_H

#include <iostream>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/url.hpp>

namespace webctl
{
    namespace asio = boost::asio;
    namespace beast = boost::beast;
    namespace ssl = asio::ssl;
    namespace http = beast::http;
    using tcp = asio::ip::tcp;

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
}

#endif