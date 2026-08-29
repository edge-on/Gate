#include "Cassandra/Scylla/Origin.hpp"

#include <iostream>
#include <thread>

bool Origin::getSSLCerts()
{
    CassStatement *statement = cass_statement_new("SELECT * FROM edgeon.ssl;", 0);

    CassFuture *future = cass_session_execute(Main::cas->session, statement);
    cass_future_wait(future);

    if (cass_future_error_code(future) == CASS_OK)
    {
        const CassResult *result = cass_future_get_result(future);
        CassIterator *iterator = cass_iterator_from_result(result);

        while (cass_iterator_next(iterator))
        {
            const CassRow *row = cass_iterator_get_row(iterator);

            const CassValue *domainVal = cass_row_get_column_by_name(row, "domain");
            const char *domain;
            size_t domainLen;
            cass_value_get_string(domainVal, &domain, &domainLen);

            const CassValue *certVal = cass_row_get_column_by_name(row, "certificate");
            const char *certificate;
            size_t certLen;
            cass_value_get_string(certVal, &certificate, &certLen);

            const CassValue *privCertVal = cass_row_get_column_by_name(row, "encrypted_privkey");
            const char *privCert;
            size_t privCertLen;
            cass_value_get_string(privCertVal, &privCert, &privCertLen);

            const CassValue *privateKeyVal = cass_row_get_column_by_name(row, "private_key");
            const char *privateKey;
            size_t privateKeyLen;
            cass_value_get_string(privateKeyVal, &privateKey, &privateKeyLen);

            std::string secretKey = Main::dotenv->map["ssl_private_key"];
            std::string decryptedText = Aes::decryptWithKey(std::string(privateKey, privateKeyLen), secretKey);

            if (decryptedText.empty())
            {
                cass_iterator_free(iterator);
                cass_result_free(result);
                cass_future_free(future);
                cass_statement_free(statement);
                return false;
            }

            std::vector<unsigned char> rawPrivateKey = Aes::base64_decode(decryptedText);
            if (rawPrivateKey.empty())
            {
                cass_iterator_free(iterator);
                cass_result_free(result);
                cass_future_free(future);
                cass_statement_free(statement);
                return false;
            }

            Kyber::KyberPayload payload = Kyber::parseKyberPayload(std::string(privCert, privCertLen));
            if (!payload.success)
            {
                cass_iterator_free(iterator);
                cass_result_free(result);
                cass_future_free(future);
                cass_statement_free(statement);
                return false;
            }

            std::vector<unsigned char> finalSharedSecret = Kyber::kyberDecrypt(payload.kyberCiphertext, rawPrivateKey);
            if (finalSharedSecret.empty())
            {
                return false;
            }

            std::string sharedSecretStr(finalSharedSecret.begin(), finalSharedSecret.end());

            std::vector<unsigned char> tlsPrivateKeyRaw = Kyber::decryptPrivateKey(
                payload.aesCiphertext,
                payload.iv,
                payload.authTag,
                sharedSecretStr);

            if (tlsPrivateKeyRaw.empty())
            {
                cass_iterator_free(iterator);
                cass_result_free(result);
                cass_future_free(future);
                cass_statement_free(statement);
                return false;
            }

            std::string tlsPrivateKeyPem(tlsPrivateKeyRaw.begin(), tlsPrivateKeyRaw.end());

            Zone *zone = Gen::H1::zones.findOrCreate(std::string_view(domain, domainLen));
            SSL_CTX *zoneCtx = SSL_CTX_new(TLS_server_method());

            BIO *cert_bio = BIO_new_mem_buf(certificate, certLen);
            X509 *cert = PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr);
            if (!cert || SSL_CTX_use_certificate(zoneCtx, cert) <= 0)
            {
                if (cert)
                    X509_free(cert);
                BIO_free(cert_bio);
            }
            X509_free(cert);

            X509 *extra_cert = nullptr;
            while ((extra_cert = PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr)) != nullptr)
            {
                SSL_CTX_add1_chain_cert(zoneCtx, extra_cert);
                X509_free(extra_cert);
            }
            BIO_free(cert_bio);

            BIO *key_bio = BIO_new_mem_buf(tlsPrivateKeyRaw.data(), static_cast<int>(tlsPrivateKeyRaw.size()));
            if (!key_bio)
            {
                SSL_CTX_free(zoneCtx);
                return false;
            }

            EVP_PKEY *pkey = PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr);
            BIO_free(key_bio);

            if (!pkey)
            {
                SSL_CTX_free(zoneCtx);
                return false;
            }

            if (SSL_CTX_use_PrivateKey(zoneCtx, pkey) <= 0)
            {
                EVP_PKEY_free(pkey);
                SSL_CTX_free(zoneCtx);
                return false;
            }
            EVP_PKEY_free(pkey);

            if (!SSL_CTX_check_private_key(zoneCtx))
            {
                SSL_CTX_free(zoneCtx);
                return false;
            }

            Gen::H1::zones.replaceCtx(zone, zoneCtx);
        }

        cass_iterator_free(iterator);
        cass_result_free(result);
    }

    cass_future_free(future);
    cass_statement_free(statement);

    return true;
}

bool Origin::getNewVersions()
{
    CassStatement *statement = cass_statement_new("SELECT * FROM edgeon.ssl_versions WHERE scope = 'scope' AND version > ?;", 1);

    cass_statement_bind_uint32(statement, 0, (uint32_t)Main::ssl->getCurrentVersion());

    CassFuture *future = cass_session_execute(Main::cas->session, statement);
    cass_future_wait(future);

    if (cass_future_error_code(future) == CASS_OK)
    {
        const CassResult *result = cass_future_get_result(future);
        CassIterator *iterator = cass_iterator_from_result(result);

        while (cass_iterator_next(iterator))
        {
            const CassRow *row = cass_iterator_get_row(iterator);

            const CassValue *domainVal = cass_row_get_column_by_name(row, "domain");
            const char *domain;
            size_t domainLen;
            cass_value_get_string(domainVal, &domain, &domainLen);

            const CassValue *certVal = cass_row_get_column_by_name(row, "certificate");
            const char *certificate;
            size_t certLen;
            cass_value_get_string(certVal, &certificate, &certLen);

            const CassValue *privCertVal = cass_row_get_column_by_name(row, "encrypted_privkey");
            const char *privCert;
            size_t privCertLen;
            cass_value_get_string(privCertVal, &privCert, &privCertLen);

            const CassValue *privateKeyVal = cass_row_get_column_by_name(row, "private_key");
            const char *privateKey;
            size_t privateKeyLen;
            cass_value_get_string(privateKeyVal, &privateKey, &privateKeyLen);

            const CassValue *versionVal = cass_row_get_column_by_name(row, "version");
            cass_int32_t v;
            cass_value_get_int32(versionVal, &v);

            if (v <= Main::ssl->getCurrentVersion())
                return false;

            Main::ssl->setVersion(v);

            std::string secretKey = Main::dotenv->map["ssl_private_key"];
            std::string decryptedText = Aes::decryptWithKey(std::string(privateKey, privateKeyLen), secretKey);

            if (decryptedText.empty())
            {
                cass_iterator_free(iterator);
                cass_result_free(result);
                cass_future_free(future);
                cass_statement_free(statement);
                return false;
            }

            std::vector<unsigned char> rawPrivateKey = Aes::base64_decode(decryptedText);
            if (rawPrivateKey.empty())
            {
                cass_iterator_free(iterator);
                cass_result_free(result);
                cass_future_free(future);
                cass_statement_free(statement);
                return false;
            }

            Kyber::KyberPayload payload = Kyber::parseKyberPayload(std::string(privCert, privCertLen));
            if (!payload.success)
            {
                cass_iterator_free(iterator);
                cass_result_free(result);
                cass_future_free(future);
                cass_statement_free(statement);
                return false;
            }

            std::vector<unsigned char> finalSharedSecret = Kyber::kyberDecrypt(payload.kyberCiphertext, rawPrivateKey);
            if (finalSharedSecret.empty())
            {
                return false;
            }

            std::string sharedSecretStr(finalSharedSecret.begin(), finalSharedSecret.end());

            std::vector<unsigned char> tlsPrivateKeyRaw = Kyber::decryptPrivateKey(
                payload.aesCiphertext,
                payload.iv,
                payload.authTag,
                sharedSecretStr);

            if (tlsPrivateKeyRaw.empty())
            {
                cass_iterator_free(iterator);
                cass_result_free(result);
                cass_future_free(future);
                cass_statement_free(statement);
                return false;
            }

            std::string tlsPrivateKeyPem(tlsPrivateKeyRaw.begin(), tlsPrivateKeyRaw.end());

            Zone *zone = Gen::H1::zones.findOrCreate(std::string_view(domain, domainLen));
            SSL_CTX *zoneCtx = SSL_CTX_new(TLS_server_method());

            BIO *cert_bio = BIO_new_mem_buf(certificate, certLen);
            X509 *cert = PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr);
            if (!cert || SSL_CTX_use_certificate(zoneCtx, cert) <= 0)
            {
                if (cert)
                    X509_free(cert);
                BIO_free(cert_bio);
            }
            X509_free(cert);

            X509 *extra_cert = nullptr;
            while ((extra_cert = PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr)) != nullptr)
            {
                SSL_CTX_add1_chain_cert(zoneCtx, extra_cert);
                X509_free(extra_cert);
            }
            BIO_free(cert_bio);

            BIO *key_bio = BIO_new_mem_buf(tlsPrivateKeyRaw.data(), static_cast<int>(tlsPrivateKeyRaw.size()));
            if (!key_bio)
            {
                SSL_CTX_free(zoneCtx);
                return false;
            }

            EVP_PKEY *pkey = PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr);
            BIO_free(key_bio);

            if (!pkey)
            {
                SSL_CTX_free(zoneCtx);
                return false;
            }

            if (SSL_CTX_use_PrivateKey(zoneCtx, pkey) <= 0)
            {
                EVP_PKEY_free(pkey);
                SSL_CTX_free(zoneCtx);
                return false;
            }
            EVP_PKEY_free(pkey);

            if (!SSL_CTX_check_private_key(zoneCtx))
            {
                SSL_CTX_free(zoneCtx);
                return false;
            }

            Gen::H1::zones.replaceCtx(zone, zoneCtx);
        }

        cass_iterator_free(iterator);
        cass_result_free(result);
    }

    cass_future_free(future);
    cass_statement_free(statement);

    return true;
}

void Origin::getSSLCert(const char *domain, const char *host, std::function<void(bool)> onDone)
{
    std::thread([domain = std::string(domain), host = std::string(host), onDone = std::move(onDone)]() mutable
                {
                    bool success = loadSSLCertForDomain(domain, host);
                    onDone(success); })
        .detach();
}

bool Origin::loadSSLCertForDomain(const std::string &domain, const std::string &host)
{
    CassStatement *statement = cass_statement_new("SELECT * FROM edgeon.ssl WHERE domain = ?;", 1);
    cass_statement_bind_string(statement, 0, domain.c_str());

    CassFuture *future = cass_session_execute(Main::cas->session, statement);
    cass_statement_free(statement);

    if (!future)
        return false;

    cass_future_wait(future);

    if (cass_future_error_code(future) != CASS_OK)
    {
        const char *message;
        size_t len;
        cass_future_error_message(future, &message, &len);
        cass_future_free(future);

        std::cerr << "Cassandra Batch Error: " << std::string(message, len) << std::endl;

        return false;
    }

    const CassResult *result = cass_future_get_result(future);
    CassIterator *iterator = cass_iterator_from_result(result);

    bool loaded = false;

    while (cass_iterator_next(iterator))
    {
        const CassRow *row = cass_iterator_get_row(iterator);

        const CassValue *certVal = cass_row_get_column_by_name(row, "certificate");
        const char *certificate;
        size_t certLen;
        cass_value_get_string(certVal, &certificate, &certLen);

        const CassValue *privCertVal = cass_row_get_column_by_name(row, "encrypted_privkey");
        const char *privCert;
        size_t privCertLen;
        cass_value_get_string(privCertVal, &privCert, &privCertLen);

        const CassValue *privateKeyVal = cass_row_get_column_by_name(row, "private_key");
        const char *privateKey;
        size_t privateKeyLen;
        cass_value_get_string(privateKeyVal, &privateKey, &privateKeyLen);

        const CassValue *versionVal = cass_row_get_column_by_name(row, "version");
        cass_int32_t v;
        cass_value_get_int32(versionVal, &v);

        if (v > Main::ssl->getCurrentVersion())
            Main::ssl->setVersion(v);

        std::string secretKey = Main::dotenv->map["ssl_private_key"];
        std::string decryptedText = Aes::decryptWithKey(std::string(privateKey, privateKeyLen), secretKey);

        if (decryptedText.empty())
            break;

        std::vector<unsigned char> rawPrivateKey = Aes::base64_decode(decryptedText);
        if (rawPrivateKey.empty())
            break;

        Kyber::KyberPayload payload = Kyber::parseKyberPayload(std::string(privCert, privCertLen));
        if (!payload.success)
            break;

        std::vector<unsigned char> finalSharedSecret = Kyber::kyberDecrypt(payload.kyberCiphertext, rawPrivateKey);
        if (finalSharedSecret.empty())
            break;

        std::string sharedSecretStr(finalSharedSecret.begin(), finalSharedSecret.end());

        std::vector<unsigned char> tlsPrivateKeyRaw = Kyber::decryptPrivateKey(
            payload.aesCiphertext,
            payload.iv,
            payload.authTag,
            sharedSecretStr);

        if (tlsPrivateKeyRaw.empty())
            break;

        OSSL_PROVIDER *defprov = OSSL_PROVIDER_load(NULL, "default");
        OSSL_PROVIDER *oqsprov = OSSL_PROVIDER_load(NULL, "oqsprovider");

        if (!oqsprov)
        {
            std::cout << "OQS PROVIDER CANNOT BE LOADED" << std::endl;
        }

        Zone *zone = Gen::H1::zones.findOrCreate(domain);
        SSL_CTX *zoneCtx = SSL_CTX_new(TLS_server_method());

        BIO *cert_bio = BIO_new_mem_buf(certificate, static_cast<int>(certLen));
        X509 *cert = PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr);
        if (!cert || SSL_CTX_use_certificate(zoneCtx, cert) <= 0)
        {
            if (cert)
                X509_free(cert);
            BIO_free(cert_bio);
            SSL_CTX_free(zoneCtx);
            break;
        }
        X509_free(cert);

        X509 *extra_cert = nullptr;
        while ((extra_cert = PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr)) != nullptr)
        {
            SSL_CTX_add1_chain_cert(zoneCtx, extra_cert);
            X509_free(extra_cert);
        }
        BIO_free(cert_bio);

        BIO *key_bio = BIO_new_mem_buf(tlsPrivateKeyRaw.data(), static_cast<int>(tlsPrivateKeyRaw.size()));
        if (!key_bio)
        {
            SSL_CTX_free(zoneCtx);
            break;
        }

        EVP_PKEY *pkey = PEM_read_bio_PrivateKey(key_bio, nullptr, nullptr, nullptr);
        BIO_free(key_bio);

        if (!pkey)
        {
            SSL_CTX_free(zoneCtx);
            break;
        }

        if (SSL_CTX_use_PrivateKey(zoneCtx, pkey) <= 0)
        {
            EVP_PKEY_free(pkey);
            SSL_CTX_free(zoneCtx);
            break;
        }
        EVP_PKEY_free(pkey);

        if (!SSL_CTX_check_private_key(zoneCtx))
        {
            SSL_CTX_free(zoneCtx);
            break;
        }

        SSL_CTX_set_cipher_list(zoneCtx, "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305");
        if (SSL_CTX_set1_groups_list(zoneCtx, "X25519MLKEM768:SecP256r1MLKEM768:x25519:P-256") != 1)
        {
            std::cout << "FAILED TO SET PQC GROUPS" << std::endl;
        }

        Gen::H1::zones.replaceCtx(zone, zoneCtx);

        loaded = true;
    }

    cass_iterator_free(iterator);
    cass_result_free(result);
    cass_future_free(future);

    return loaded;
}

void Origin::insertStatsAsync()
{
    std::thread([]() mutable
                { insertStatsSync(); })
        .detach();
}

bool Origin::insertStatsSync()
{
    const char *query = "INSERT INTO edgeon.domain_stats (domain, type, date, value, host) VALUES (?, ?, ?, ?, ?)";

    CassFuture *prep_future = cass_session_prepare(Main::cas->session, query);

    if (!cass_future_wait_timed(prep_future, 5000000))
    {
        cass_future_free(prep_future);
        return false;
    }

    if (cass_future_error_code(prep_future) != CASS_OK)
    {
        const char *message;
        size_t len;
        cass_future_error_message(prep_future, &message, &len);
        std::cerr << "ERR Prepare: " << std::string(message, len) << std::endl;
        cass_future_free(prep_future);
        return false;
    }

    const CassPrepared *prepared = cass_future_get_prepared(prep_future);
    cass_future_free(prep_future);

    CassBatch *batch = cass_batch_new(CASS_BATCH_TYPE_UNLOGGED);

    cass_int64_t now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                              std::chrono::system_clock::now().time_since_epoch())
                              .count();

    Gen::H1::zones.forEach([&](const std::string &domain, Zone &zone)
                       {
        const std::pair<int, int64_t> metrics[] = {
            {1, zone.dnsQueries.exchange(0, std::memory_order_relaxed)},
            {2, zone.inbound.exchange(0, std::memory_order_relaxed)},
            {3, zone.outbound.exchange(0, std::memory_order_relaxed)}};

        for (const auto &[type, value] : metrics)
        {
            if(value <= 0)
                continue;

            CassStatement *statement = cass_prepared_bind(prepared);

            cass_statement_bind_string(statement, 0, zone.domain.c_str());
            cass_statement_bind_int32(statement, 1, type);
            cass_statement_bind_int64(statement, 2, now_ms);
            cass_statement_bind_int64(statement, 3, value);
            cass_statement_bind_string(statement, 4, zone.host.data());

            cass_batch_add_statement(batch, statement);
            cass_statement_free(statement);
        } });

    CassFuture *future = cass_session_execute_batch(Main::cas->session, batch);
    cass_batch_free(batch);
    cass_prepared_free(prepared);

    if (!future)
        return false;

    cass_future_wait(future);

    bool success = true;
    if (cass_future_error_code(future) != CASS_OK)
    {
        const char *message;
        size_t len;
        cass_future_error_message(future, &message, &len);
        std::cerr << "Cassandra Batch Error: " << std::string(message, len) << std::endl;
        success = false;
    }

    cass_future_free(future);
    return success;
}