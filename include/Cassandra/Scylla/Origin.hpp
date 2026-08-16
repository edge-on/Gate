#pragma once

#include <string>
#include <string_view>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>

#include "Utils/Crypto/Aes.hpp"
#include "Utils/Crypto/Kyber.hpp"

#include "Main.hpp"

class Origin
{
public:
    static std::string getOrigin(std::string host);
    static bool getSSLCerts();

    static bool getNewVersions();

    // static std::string getAcmeToken(std::string host, std::string token);
};