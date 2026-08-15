#pragma once

#include <maxminddb.h>

#include <sys/stat.h>
#include <sys/fcntl.h>
#include <unistd.h>

#include <iostream>

#include <string>

#include <vector>

namespace Maxmind
{
    class DB
    {
    public:
        static void init(const char *path);
        static std::string getVal(char *val);

        static inline const std::vector<std::string> blockedProviders = {
            "amazon", "aws", "digitalocean", "hetzner", "ovh",
            "linode", "vultr", "contabo", "oracle", "scaleway",
            "leaseweb", "m247", "choopa", "cogent"};

    private:
        static MMDB_s mmdb;
    };
} // namespace Maxmind
