#include "Core/Security/Headers.hpp"

Security::Headers::RequestStatus Security::Headers::validateReq(char *req, ssize_t len)
{
    if (Utils::Http::getHost(req, len) == "undefined" ||
        Utils::Http::getPath(req, len).empty())
    {
        return RequestStatus::INVALID_HTTP;
    }

    std::string userAgent = Utils::Http::getHeader(req, len, "user-agent:");
    if (userAgent == "undefined" || isBotUserAgent(userAgent))
    {
        return RequestStatus::BLOCKED;
    }

    if (Utils::Http::getHeader(req, len, "accept-language:") == "undefined" ||
        Utils::Http::getHeader(req, len, "accept-encoding:") == "undefined")
    {
        return RequestStatus::BLOCKED;
    }

    return RequestStatus::VALID_CLIENT;
}

bool Security::Headers::isBotUserAgent(const std::string &userAgent)
{
    if (userAgent.empty() || userAgent == "undefined" || userAgent.length() < 15)
    {
        return true;
    }

    std::string lowerUa = userAgent;
    std::transform(lowerUa.begin(), lowerUa.end(), lowerUa.begin(),
                   [](unsigned char c)
                   { return std::tolower(c); });

    static const std::vector<std::string> allowedBotKeywords = {
        "googlebot",
        "google-inspectiontool",
        "googleother",
        "adsbot-google",
        "mediapartners-google",
        "apis-google",
        "bingbot",
        "msnbot",
        "bingpreview",
        "slurp",
        "duckduckbot",
        "baiduspider",
        "yandexbot",
        "sogou",
        "exabot",
        "facebookexternalhit",
        "twitterbot",
        "linkedinbot",
        "applebot",
        "petalbot",
    };

    for (const auto &keyword : allowedBotKeywords)
    {
        if (lowerUa.find(keyword) != std::string::npos)
        {
            return false;
        }
    }

    if (userAgent.length() < 30)
    {
        return true;
    }

    if (userAgent.find("Mozilla/5.0") == std::string::npos)
    {
        return true;
    }

    static const std::vector<std::string> botKeywords = {
        "curl", "wget", "python", "urllib", "requests", "axios", "node-fetch",
        "go-http-client", "java/", "libwww", "php", "postman", "insomnia",
        "headlesschrome", "puppeteer", "selenium", "phantomjs", "playwright",
        "bot", "spider", "crawler", "scraper", "archiver"};

    for (const auto &keyword : botKeywords)
    {
        if (lowerUa.find(keyword) != std::string::npos)
        {
            return true;
        }
    }

    static const std::vector<std::string> browserKeywords = {
        "chrome", "firefox", "safari", "edg", "opera", "applewebkit", "gecko"};

    bool hasBrowserToken = false;
    for (const auto &keyword : browserKeywords)
    {
        if (lowerUa.find(keyword) != std::string::npos)
        {
            hasBrowserToken = true;
            break;
        }
    }

    if (!hasBrowserToken)
    {
        return true;
    }

    if (lowerUa.find("windows nt") != std::string::npos && lowerUa.find("android") != std::string::npos)
    {
        return true;
    }

    return false;
}