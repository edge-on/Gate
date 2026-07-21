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

std::string Origin::getAcmeToken(std::string host, std::string token)
{
    CassStatement *statement = cass_statement_new("SELECT * FROM edgeon.acme WHERE host = ? AND token = ?;", 2);
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
}