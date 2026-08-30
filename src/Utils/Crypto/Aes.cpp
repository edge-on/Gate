#include "Utils/Crypto/Aes.hpp"

std::vector<unsigned char> Aes::hex_to_bytes(const std::string &hex)
{
    std::vector<unsigned char> bytes;
    for (size_t i = 0; i < hex.length(); i += 2)
    {
        std::string byteString = hex.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(strtol(byteString.c_str(), nullptr, 16));
        bytes.push_back(byte);
    }
    return bytes;
}

std::vector<unsigned char> Aes::base64_decode(const std::string &in)
{
    if (in.empty())
        return {};

    if (in.size() % 4 != 0)
        return {};

    std::vector<unsigned char> buffer(in.size() / 4 * 3);

    int decoded_len = EVP_DecodeBlock(buffer.data(), reinterpret_cast<const unsigned char *>(in.data()), static_cast<int>(in.size()));

    if (decoded_len < 0)
        return {};

    int padding = 0;
    if (in.size() >= 1 && in[in.size() - 1] == '=')
        padding++;
    if (in.size() >= 2 && in[in.size() - 2] == '=')
        padding++;

    decoded_len -= padding;
    if (decoded_len < 0)
        return {};

    buffer.resize(decoded_len);
    return buffer;
}

std::string Aes::decryptWithKey(const std::string &base64Packet, const std::string &rawSecretKey)
{
    std::vector<unsigned char> packetBytes = base64_decode(base64Packet);
    std::string packetStr(packetBytes.begin(), packetBytes.end());

    std::stringstream ss(packetStr);
    std::string ivHex, authTagHex, encryptedHex;

    if (!std::getline(ss, ivHex, ':') ||
        !std::getline(ss, authTagHex, ':') ||
        !std::getline(ss, encryptedHex, ':'))
    {
        return "";
    }

    std::vector<unsigned char> iv = hex_to_bytes(ivHex);
    std::vector<unsigned char> authTag = hex_to_bytes(authTagHex);
    std::vector<unsigned char> ciphertext = hex_to_bytes(encryptedHex);
    std::vector<unsigned char> secretKey(rawSecretKey.begin(), rawSecretKey.end());

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return "";

    std::vector<unsigned char> plaintext(ciphertext.size());
    int len = 0, plaintext_len = 0;
    bool success = false;

    try
    {
        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
            throw 0;
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), iv.data()))
            throw 0;
        if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, secretKey.data(), iv.data()))
            throw 0;

        if (1 != EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ciphertext.size()))
            throw 0;
        plaintext_len = len;

        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, authTag.size(), authTag.data()))
            throw 0;

        if (1 == EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len))
        {
            plaintext_len += len;
            success = true;
        }
    }
    catch (...)
    {
        success = false;
    }

    EVP_CIPHER_CTX_free(ctx);

    if (!success)
        return "";

    return std::string(plaintext.begin(), plaintext.begin() + plaintext_len);
}