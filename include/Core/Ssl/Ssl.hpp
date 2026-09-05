#pragma once

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/evp.h>

#include <thread>
#include <future>
#include <chrono>

#include <iostream>

#include <quiche.h>

#include <string>

#include "Core/Gen/H1/Gen.hpp"
#include "Core/Gen/H3/Gen.hpp"

#include "Utils/Http.hpp"

#include "Cassandra/Scylla/Origin.hpp"

class Ssl
{
public:
    static SSL_CTX *initSSL();
    static quiche_config *initQuicheSSL();

    static int alpn_cb(SSL *ssl, const unsigned char **out, unsigned char *outlen, const unsigned char *in, unsigned int inlen, void *arg);
    static enum ssl_select_cert_result_t client_hello_cb(const SSL_CLIENT_HELLO *client_hello);

    static void debugLog(const char *line, void *argp);
};