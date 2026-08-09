#pragma once

#include <signal.h>

#include "Core/Core.hpp"

#include "Dotenv/Dotenv.hpp"
#include "Cassandra/Cassandra.hpp"

#include "DNS/DNSClient.hpp"

class Main
{
public:
    static Dotenv *dotenv;
    static Cassandra *cas;

    static std::vector<int> listeners;

    static char* resolverIp;
};