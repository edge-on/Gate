#pragma once

#include <string>
#include <string_view>

#include "Utils/Crypto.hpp"

#include "Main.hpp"

class Origin
{
public:
    static std::string getOrigin(std::string host);
    static bool getSSLCerts();
    // static std::string getAcmeToken(std::string host, std::string token);
};