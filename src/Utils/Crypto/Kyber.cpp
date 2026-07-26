#include "Utils/Crypto/Kyber.hpp"

Kyber::KyberPayload Kyber::parseKyberPayload(const std::string &jsonInput)
{
    KyberPayload payload;
    try
    {
        auto j = nlohmann::json::parse(jsonInput);
        if (j.is_string())
        {
            j = nlohmann::json::parse(j.get<std::string>());
        }

        payload.kyberCiphertext = Aes::hex_to_bytes(j["kyberCiphertext"].get<std::string>());
        payload.aesCiphertext = Aes::hex_to_bytes(j["aesCiphertext"].get<std::string>());
        payload.iv = Aes::hex_to_bytes(j["iv"].get<std::string>());
        payload.authTag = Aes::hex_to_bytes(j["authTag"].get<std::string>());
        payload.success = true;
    }
    catch (const std::exception &e)
    {
        std::cerr << "JSON Parse Error: " << e.what() << std::endl;
        payload.success = false;
    }
    return payload;
}

std::vector<unsigned char> Kyber::decryptPrivateKey(const std::vector<unsigned char> &encrypted_pk, const std::vector<unsigned char> &iv, const std::vector<unsigned char> &authTag, const std::string &rawSecretKey)
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

std::vector<unsigned char> Kyber::kyberDecrypt(const std::vector<unsigned char> &ciphertext, const std::vector<unsigned char> &decrypted_private_key)
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