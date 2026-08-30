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

    SSL_CTX_set_cipher_list(ctx, "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305");
    if (SSL_CTX_set1_groups_list(ctx, "X25519Kyber768Draft00:x25519:P-256") != 1)
    {
        std::cout << "FAILED TO SET PQC GROUPS" << std::endl;
    }

    SSL_CTX_set_mode(ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    SSL_CTX_set_select_certificate_cb(ctx, Ssl::client_hello_cb);

    return ctx;
}

quiche_config *Ssl::initQuicheSSL()
{
    quiche_config *conf = quiche_config_new(QUICHE_PROTOCOL_VERSION);
    quiche_config_load_cert_chain_from_pem_file(conf, "SSL/localhost.pem");
    quiche_config_load_priv_key_from_pem_file(conf, "SSL/localhost-key.pem");

    return conf;
}

int Ssl::alpn_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg)
{
    auto *connDbg = static_cast<::H1::Gen::H1Connection *>(SSL_get_app_data(ssl));
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

enum ssl_select_cert_result_t Ssl::client_hello_cb(const SSL_CLIENT_HELLO *client_hello)
{
    SSL *ssl = client_hello->ssl;

    auto *conn = static_cast<::H1::Gen::H1Connection *>(SSL_get_app_data(ssl));
    if (!conn)
    {
        return ssl_select_cert_error;
    }

    const unsigned char *extData = nullptr;
    size_t extLen = 0;

    if (!SSL_early_callback_ctx_extension_get(client_hello, TLSEXT_TYPE_server_name, &extData, &extLen) || extLen < 5)
    {
        conn->missingSni = true;
        return ssl_select_cert_success;
    }

    size_t nameLen = (static_cast<size_t>(extData[3]) << 8) | extData[4];
    if (5 + nameLen > extLen)
    {
        return ssl_select_cert_error;
    }

    std::string domain(reinterpret_cast<const char *>(extData + 5), nameLen);
    conn->zone = Gen::zones.findOrCreate(domain);

    const char *root = Utils::Http::getRootDomainPtr(domain.c_str(), domain.size());
    std::string rootDomain(root, domain.c_str() + domain.size() - root);
    conn->domain = rootDomain;
    conn->zone->domain = rootDomain;
    conn->zone->host = domain;

    Zone *zone = Gen::zones.find(rootDomain);
    if (zone)
    {
        SSL_CTX *zoneCtx = zone->ctx.load(std::memory_order_acquire);
        if (zoneCtx)
        {
            SSL_set_SSL_CTX(ssl, zoneCtx);
            return ssl_select_cert_success;
        }
    }

    if (conn->protocolState == ::H1::Gen::TCP_PENDING_SSL)
        return ssl_select_cert_retry;

    conn->protocolState = ::H1::Gen::TCP_PENDING_SSL;

    int threadId = conn->thread;
    int fd = conn->fd;

    Origin::getSSLCert(rootDomain.c_str(), domain.c_str(), [threadId, fd](bool success)
                       { Gen::activeThreads[threadId].wakeup.push({threadId, fd, success}); });

    return ssl_select_cert_retry;
}