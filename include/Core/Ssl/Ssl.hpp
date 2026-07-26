#pragma once

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include <string>

#include "Core/Gen/Gen.hpp"

class Ssl
{
public:
    static SSL_CTX *initSSL();

private:
    static int alpn_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg);
    static int sni_callback(SSL *ssl, int *ad, void *arg);
};