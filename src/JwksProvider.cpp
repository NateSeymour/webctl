#include "JwksProvider.h"
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/param_build.h>
#include <cppcodec/base64_url_unpadded.hpp>

using base64 = cppcodec::base64_url_unpadded;

using namespace webctl;

std::expected<JWT, JWTError> JWT::FromToken(JWKSProvider &jwks_provider, std::string_view token)
{
    JWT jwt{};

    // Parse token
    std::vector<std::string> token_parts;
    token_parts.reserve(3);
    boost::split(token_parts, token, boost::is_any_of("."));

    if (token_parts.size() != 3)
    {
        return std::unexpected{JWTError::Malformed};
    }

    auto header_raw = base64::decode(token_parts[0]);
    auto header = json::parse(std::string_view{(char*)header_raw.data(), header_raw.size()});

    auto claims_raw = base64::decode(token_parts[1]);
    auto claims = json::parse(std::string_view{(char*)claims_raw.data(), claims_raw.size()});

    std::string payload = token_parts[0] + "." + token_parts[1];
    auto sig = base64::decode(token_parts[2]);

    auto key = jwks_provider.GetKeyById(header.as_object()["kid"].as_string().data());
    if (!key)
    {
        return std::unexpected{JWTError::NoKey};
    }

    // Build key
    EVP_PKEY_CTX *evp_ctx = EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr);
    EVP_PKEY *pkey = nullptr;

    std::string e_base64 = key.value().as_object()["e"].as_string().data();
    std::string n_base64 = key.value().as_object()["n"].as_string().data();

    auto e = base64::decode(e_base64);
    auto n = base64::decode(n_base64);

    OSSL_PARAM_BLD *param_bld = OSSL_PARAM_BLD_new();

    BIGNUM *e_bn = BN_bin2bn(e.data(), static_cast<int>(e.size()), nullptr);
    BIGNUM *n_bn = BN_bin2bn(n.data(), static_cast<int>(n.size()), nullptr);

    OSSL_PARAM_BLD_push_BN(param_bld, "n", n_bn);
    OSSL_PARAM_BLD_push_BN(param_bld, "e", e_bn);

    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param(param_bld);

    if (auto err = EVP_PKEY_fromdata_init(evp_ctx); err <= 0)
    {
        std::cerr << ERR_error_string(err, nullptr) << std::endl;
    }

    if (auto err = EVP_PKEY_fromdata(evp_ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params); err <= 0)
    {
        std::cerr << ERR_error_string(err, nullptr) << std::endl;
    }

    // Verify signature
    EVP_MD_CTX *md_ctx = EVP_MD_CTX_create();

    EVP_MD const *md = EVP_get_digestbyname("SHA256");
    if (!md)
    {
        EVP_MD_CTX_free(md_ctx);
        return std::unexpected{JWTError::Invalid};
    }

    EVP_VerifyInit(md_ctx, md);

    EVP_VerifyUpdate(md_ctx, payload.c_str(), payload.size());
    int valid = EVP_VerifyFinal(md_ctx, sig.data(), sig.size(), pkey);

    EVP_PKEY_CTX_free(evp_ctx);
    EVP_PKEY_free(pkey);
    BN_free(e_bn);
    BN_free(n_bn);
    OSSL_PARAM_BLD_free(param_bld);
    OSSL_PARAM_free(params);
    EVP_MD_CTX_free(md_ctx);
}