#ifndef JWKS_PROVIDER_H
#define JWKS_PROVIDER_H

#include <string_view>

namespace webctl
{
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
        [[nodiscard]] std::optional<json::value> GetKeyById(const std::string& kid)
        {
            std::lock_guard lk(this->m_jwks_);

            if (this->jwks_.keys.contains(kid))
            {
                return this->jwks_.keys.at(kid);
            }

            return std::nullopt;
        }

        JWKSProvider(asio::io_context &ioc, HTTPClient &http_client) : ioc_(ioc), http_client_(http_client)
        {
            std::cout << "[JWKSProvider] Initializing..." << std::endl;

            asio::co_spawn(this->ioc_, this->FetchJWKS(), asio::detached);
        }
    };

    struct JWT
    {
        static JWT FromToken(std::string_view token);
    };
} // namespace webctl

#endif