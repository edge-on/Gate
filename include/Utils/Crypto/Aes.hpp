#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include <nlohmann/json.hpp>

class Aes
{
public:
    static std::vector<unsigned char> hex_to_bytes(const std::string &hex);
    static std::vector<unsigned char> base64_decode(const std::string &in);
    static std::string decryptWithKey(const std::string &base64Packet, const std::string &rawSecretKey);
};