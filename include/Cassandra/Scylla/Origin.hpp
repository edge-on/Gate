#pragma once

#include <string>
#include <string_view>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "Utils/Crypto/Aes.hpp"
#include "Utils/Crypto/Kyber.hpp"

#include <cassandra.h>

#include "Main.hpp"

class Origin
{
public:
    struct SSLCertAsyncContext
    {
        std::string domain;
        std::function<void(bool)> onDone;
    };

    static std::string getOrigin(std::string host);
    static bool getSSLCerts();

    static bool getNewVersions();

    static void getSSLCert(const char *domain, std::function<void(bool)> onDone);

    static void finishSSLCert(SSLCertAsyncContext *ctx, bool success, CassIterator *iterator = nullptr, const CassResult *result = nullptr);
    static void onSSLCertFutureReady(CassFuture *future, void *data);
};