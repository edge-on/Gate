#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

#include <nlohmann/json.hpp>

#include <oqs/oqs.h>

struct KyberPayload
{
    std::vector<unsigned char> kyberCiphertext;
    std::vector<unsigned char> aesCiphertext;
    std::vector<unsigned char> iv;
    std::vector<unsigned char> authTag;
    bool success = false;
};

static std::vector<unsigned char> hex_to_bytes(const std::string &hex)
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

static KyberPayload parseKyberPayload(const std::string &jsonInput)
{
    KyberPayload payload;
    try
    {
        auto j = nlohmann::json::parse(jsonInput);
        if (j.is_string())
        {
            j = nlohmann::json::parse(j.get<std::string>());
        }

        payload.kyberCiphertext = hex_to_bytes(j["kyberCiphertext"].get<std::string>());
        payload.aesCiphertext = hex_to_bytes(j["aesCiphertext"].get<std::string>());
        payload.iv = hex_to_bytes(j["iv"].get<std::string>());
        payload.authTag = hex_to_bytes(j["authTag"].get<std::string>());
        payload.success = true;
    }
    catch (const std::exception &e)
    {
        std::cerr << "JSON Parse Error: " << e.what() << std::endl;
        payload.success = false;
    }
    return payload;
}

static std::vector<unsigned char> decryptPrivateKey(const std::vector<unsigned char> &encrypted_pk, const std::vector<unsigned char> &iv, const std::vector<unsigned char> &authTag, const std::string &rawSecretKey)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return {};

    std::vector<unsigned char> decrypted_pk(encrypted_pk.size());
    int len = 0, plaintext_len = 0;
    bool success = false;
    std::vector<unsigned char> secretKey(rawSecretKey.begin(), rawSecretKey.end());

    try
    {
        if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
            throw 0;
        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), (void *)iv.data()))
            throw 0;
        if (1 != EVP_DecryptInit_ex(ctx, NULL, NULL, secretKey.data(), iv.data()))
            throw 0;

        if (1 != EVP_DecryptUpdate(ctx, decrypted_pk.data(), &len, encrypted_pk.data(), encrypted_pk.size()))
            throw 0;
        plaintext_len = len;

        if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, authTag.size(), (void *)authTag.data()))
            throw 0;

        if (1 == EVP_DecryptFinal_ex(ctx, decrypted_pk.data() + len, &len))
        {
            plaintext_len += len;
            decrypted_pk.resize(plaintext_len);
            success = true;
        }
    }
    catch (...)
    {
        success = false;
    }

    EVP_CIPHER_CTX_free(ctx);
    if (!success)
        return {};
    return decrypted_pk;
}

static std::vector<unsigned char> kyberDecrypt(const std::vector<unsigned char> &ciphertext, const std::vector<unsigned char> &decrypted_private_key)
{
    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    if (kem == NULL)
    {
        std::cerr << "Kyber algorithm cannot be start!" << std::endl;
        return {};
    }

    std::vector<unsigned char> shared_secret(kem->length_shared_secret);

    if (OQS_KEM_decaps(kem, shared_secret.data(), ciphertext.data(), decrypted_private_key.data()) != OQS_SUCCESS)
    {
        std::cerr << "Kyber decap is not successfull!" << std::endl;
        OQS_KEM_free(kem);
        return {};
    }

    OQS_KEM_free(kem);
    return shared_secret;
}

static std::vector<unsigned char> base64_decode(const std::string &in)
{
    BIO *bio, *b64;
    std::vector<unsigned char> buffer(in.size());

    b64 = BIO_new(BIO_f_base64());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    bio = BIO_new_mem_buf(in.data(), static_cast<int>(in.size()));
    bio = BIO_push(b64, bio);

    int decoded_len = BIO_read(bio, buffer.data(), static_cast<int>(in.size()));
    BIO_free_all(bio);

    if (decoded_len < 0)
        return {};
    buffer.resize(decoded_len);
    return buffer;
}

static std::string decryptWithKey(const std::string &base64Packet, const std::string &rawSecretKey)
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