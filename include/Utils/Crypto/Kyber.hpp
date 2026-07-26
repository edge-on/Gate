#pragma once

#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include <nlohmann/json.hpp>
#include <oqs/oqs.h>

#include "Aes.hpp"

class Kyber
{
public:
    struct KyberPayload
    {
        std::vector<unsigned char> kyberCiphertext;
        std::vector<unsigned char> aesCiphertext;
        std::vector<unsigned char> iv;
        std::vector<unsigned char> authTag;
        bool success = false;
    };

    static KyberPayload parseKyberPayload(const std::string &jsonInput);
    static std::vector<unsigned char> decryptPrivateKey(const std::vector<unsigned char> &encrypted_pk, const std::vector<unsigned char> &iv, const std::vector<unsigned char> &authTag, const std::string &rawSecretKey);
    static std::vector<unsigned char> kyberDecrypt(const std::vector<unsigned char> &ciphertext, const std::vector<unsigned char> &decrypted_private_key);
};