#ifndef JWKS_PROVIDER_H
#define JWKS_PROVIDER_H

#include <string_view>
#include <mutex>
#include <optional>
#include <expected>
#include <boost/asio.hpp>
#include <boost/json.hpp>
#include <boost/url.hpp>
#include "HTTPClient.h"

namespace webctl
{
    namespace asio = boost::asio;
    namespace json = boost::json;

    enum class JWTError
    {
        Malformed,
        Invalid,
        NoKey,
    };

    struct JWT
    {};

    struct JWKS
    {
        std::unordered_map<std::string, json::value> keys;

        [[nodiscard]] static std::optional<JWKS> FromJson(json::value raw);
    };

    class OIDCProvider
    {
        asio::io_context &ioc_;
        HTTPClient &http_client_;
        boost::url authority_;

        JWKS jwks_;
        std::mutex m_jwks_;

        asio::awaitable<void> FetchJWKS();

    public:
        [[nodiscard]] std::optional<json::value> GetKeyById(const std::string& kid);

        [[nodiscard]] std::expected<JWT, JWTError> ValidateToken(std::string_view token);

        OIDCProvider(asio::io_context &ioc, HTTPClient &http_client, boost::url authority);
    };
} // namespace webctl

#endif