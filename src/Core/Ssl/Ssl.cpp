#include "Core/Ssl/Ssl.hpp"

SSL_CTX *Ssl::initSSL()
{
    SSL_CTX *ctx;

    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_use_certificate_chain_file(ctx, "SSL/localhost.pem");
    SSL_CTX_use_PrivateKey_file(ctx, "SSL/localhost-key.pem", SSL_FILETYPE_PEM);

    SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:x25519_kyber768:x25519:P-256");

    SSL_CTX_set_mode(ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    SSL_CTX_set_client_hello_cb(ctx, Ssl::client_hello_cb, nullptr);

    return ctx;
}

int Ssl::alpn_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg)
{
    auto *connDbg = static_cast<Gen::Connection *>(SSL_get_app_data(ssl));
    int *force_flag = (int *)SSL_get_app_data(ssl);

    if (force_flag && *force_flag == 1)
    {
        *out = (unsigned char *)"http/1.1";
        *outlen = 8;
        return SSL_TLSEXT_ERR_OK;
    }

    if (SSL_select_next_proto((unsigned char **)out, outlen, in, inlen,
                              (unsigned char *)"\x02h2\x08http/1.1", 11) == OPENSSL_NPN_NEGOTIATED)
    {
        return SSL_TLSEXT_ERR_OK;
    }

    return SSL_TLSEXT_ERR_NOACK;
}

int Ssl::client_hello_cb(SSL *ssl, int *al, void *arg)
{
    auto *conn = static_cast<Gen::Connection *>(SSL_get_app_data(ssl));
    if (!conn)
    {
        *al = SSL_AD_INTERNAL_ERROR;
        return SSL_CLIENT_HELLO_ERROR;
    }

    const unsigned char *extData = nullptr;
    size_t extLen = 0;

    if (!SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_server_name, &extData, &extLen) || extLen < 5)
    {
        conn->missingSni = true;
        return SSL_CLIENT_HELLO_SUCCESS;
    }

    size_t nameLen = (static_cast<size_t>(extData[3]) << 8) | extData[4];
    if (5 + nameLen > extLen)
    {
        *al = SSL_AD_UNRECOGNIZED_NAME;
        return SSL_CLIENT_HELLO_ERROR;
    }

    std::string domain(reinterpret_cast<const char *>(extData + 5), nameLen);
    const char *root = Utils::Http::getRootDomainPtr(domain.c_str(), domain.size());
    std::string rootDomain(root, domain.c_str() + domain.size() - root);
    
    auto it = Gen::zones.find(rootDomain);
    if (it != Gen::zones.end() && it->second.ctx != nullptr)
    {
        SSL_set_SSL_CTX(ssl, it->second.ctx);
        return SSL_CLIENT_HELLO_SUCCESS;
    }

    if (conn->protocolState == Gen::TCP_PENDING_SSL)
        return SSL_CLIENT_HELLO_RETRY;

    conn->protocolState = Gen::TCP_PENDING_SSL;

    int threadId = conn->thread;
    int fd = conn->fd;

    Origin::getSSLCert(rootDomain.c_str(), [threadId, fd](bool success)
                       { Gen::activeThreads[threadId].wakeup.push({threadId, fd, success}); });

    return SSL_CLIENT_HELLO_RETRY;
}
