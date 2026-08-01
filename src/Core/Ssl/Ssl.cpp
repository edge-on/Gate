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

    SSL_CTX_set_mode(ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    SSL_CTX_callback_ctrl(ctx, SSL_CTRL_SET_TLSEXT_SERVERNAME_CB, reinterpret_cast<void (*)()>(Ssl::sni_callback));

    // Here is for HTTP2
    // SSL_CTX_set_cipher_list(ctx, "ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384");
    // SSL_CTX_set_ecdh_auto(ctx, 1);
    // SSL_CTX_set_alpn_select_cb(ctx, Ssl::alpn_cb, NULL);

    return ctx;
}

int Ssl::alpn_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg)
{

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

int Ssl::sni_callback(SSL *ssl, int *ad, void *arg)
{
    const char *domain = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
    if (!domain)
        return SSL_TLSEXT_ERR_NOACK;

    std::string host = Utils::Http::getHost(domain, sizeof(domain));

    auto it = Gen::zones.find(host.data());

    if (it == Gen::zones.end() || it->second.ctx == nullptr)
        return SSL_TLSEXT_ERR_NOACK;

    SSL_set_SSL_CTX(ssl, it->second.ctx);
    return SSL_TLSEXT_ERR_OK;
}