#pragma once

#include <signal.h>

#include <hiredis/hiredis.h>

#include "Utils/String.hpp"

#include "Core/Core.hpp"

#include "Mmap/SSL.hpp"

#include "Dotenv/Dotenv.hpp"
#include "Cassandra/Cassandra.hpp"

#include "DNS/DNSClient.hpp"

#include "Maxmind/DB.hpp"

class Main
{
public:
    static Dotenv *dotenv;
    static Cassandra *cas;

    static std::vector<int> listeners;

    static char *resolverIp;

    static redisContext *redis;

    static std::string country;
    static std::string city;
    static std::string code;

    static Mmap::SSL *ssl;

    static bool isQuicheLogging;
};