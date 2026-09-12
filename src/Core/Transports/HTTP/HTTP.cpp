#include "Core/Transports/HTTP/HTTP.hpp"

void Transports::HTTP::parseHttp(char *b, ssize_t length, ::H3::Gen::ReqIOCtx &req)
{
    std::string_view data = std::string_view(b);

    if (data.find("\r\n\r\n") != std::string::npos)
        req.haveHeaders = true;

    if (req.haveHeaders)
    {
        std::string_view firstLine = data.substr(0, data.find("\n"));

        // For base data
        std::vector<std::string_view> results;
        ssize_t start = 0;
        ssize_t end = firstLine.find(" ");

        while (end != std::string::npos)
        {
            results.push_back(firstLine.substr(start, end - start));
            start = end + 1;
            end = firstLine.find(" ", start);
        }

        results.push_back(firstLine.substr(start));

        if (results.size() <= 1)
            return;

        req.status = strndup(results[1].data(), results[1].size()); // Status = Indis 1

        // For headers
        auto headers = data.substr(data.find("\n") + 1, data.find("\r\n\r\n") - data.find("\n") - 1);

        start = 0;
        end = headers.find("\r\n");

        while (end != std::string::npos)
        {
            req.headers.push_back(headers.substr(start, end - start));
            start = end + 2;
            end = headers.find("\r\n", start);
        }

        req.headers.push_back(headers.substr(start));

        // For body
        auto body = data.substr(data.find("\r\n\r\n") + 4, data.size() - data.find("\r\n\r\n") - 4);

        req.body = strndup(body.data(), body.size());
    }
    else
    {
        req.body = b;
    }
}