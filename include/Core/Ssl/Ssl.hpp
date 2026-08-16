#pragma once

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include <thread>
#include <future>
#include <chrono>

#include <string>

#include "Core/Gen/Gen.hpp"

#include "Utils/Http.hpp"

#include "Cassandra/Scylla/Origin.hpp"

class Ssl
{
public:
    static SSL_CTX *initSSL();

private:
    static int alpn_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg);
    static int client_hello_cb(SSL *ssl, int *al, void *arg);
};