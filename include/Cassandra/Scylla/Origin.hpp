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
    static std::string getOrigin(std::string host);
    static bool getSSLCerts();
    static bool getNewVersions();

    static void getSSLCert(const char *domain, std::function<void(bool)> onDone);
    static void insertStatsAsync();

private:
    static bool loadSSLCertForDomain(const std::string &domain);
    static bool insertStatsSync();
};