#include "Cassandra/Scylla/Origin.hpp"

// Allow filtering will be removed
std::string Origin::getOrigin(std::string host)
{
    CassStatement *statement = cass_statement_new("SELECT * FROM edgeon.records WHERE name = ? AND type = 1 ALLOW FILTERING;", 1);
    cass_statement_bind_string(statement, 0, host.data());

    CassFuture *future = cass_session_execute(Main::cas->session, statement);
    cass_future_wait(future);

    if (cass_future_error_code(future) == CASS_OK)
    {
        const CassResult *result = cass_future_get_result(future);
        CassIterator *iterator = cass_iterator_from_result(result);

        while (cass_iterator_next(iterator))
        {
            const CassRow *row = cass_iterator_get_row(iterator);

            const CassValue *val = cass_row_get_column_by_name(row, "value");

            const char *value;
            size_t len;

            cass_value_get_string(val, &value, &len);

            return value;
        }
    }

    return "";
}

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
            std::cout << "PEM:\n"
                      << tlsPrivateKeyPem << std::endl;
        }

        cass_iterator_free(iterator);
        cass_result_free(result);
    }

    cass_future_free(future);
    cass_statement_free(statement);

    return true;
}

// We remove HTTP-01 ACME Verification because we cannot get ssl's that support wildcard with HTTP-01 ACME
/*std::string Origin::getAcmeToken(std::string host, std::string token)
{
    CassStatement *statement = cass_statement_new("SELECT * FROM edgeon.acme WHERE host = ? AND \"token\" = ?;", 2);
    cass_statement_bind_string(statement, 0, host.data());
    cass_statement_bind_string(statement, 1, token.data());

    CassFuture *future = cass_session_execute(Main::cas->session, statement);
    cass_future_wait(future);

    if (cass_future_error_code(future) == CASS_OK)
    {
        const CassResult *result = cass_future_get_result(future);
        CassIterator *iterator = cass_iterator_from_result(result);

        while (cass_iterator_next(iterator))
        {
            const CassRow *row = cass_iterator_get_row(iterator);

            const CassValue *val = cass_row_get_column_by_name(row, "value");

            const char *value;
            size_t len;

            cass_value_get_string(val, &value, &len);

            return value;
        }
    }

    return "";
}*/