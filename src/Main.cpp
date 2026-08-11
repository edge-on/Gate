#include "Main.hpp"

Dotenv *Main::dotenv;
Cassandra *Main::cas;

std::vector<int> Main::listeners;

char *Main::resolverIp;

redisContext *Main::redis;

int main(int argc, char *argv[])
{
    Main::dotenv = new Dotenv();
    Main::dotenv->config(".env");

    Main::redis = redisConnect(Main::dotenv->map["redis_host"].data(), 6379);

    if(Main::redis == NULL || Main::redis->err) {
        if(Main::redis) {
            std::cout << "Redis connection is not successfull." << std::endl;
            redisFree(Main::redis);
        } else {
            std::cout << "Redis context is not created successfully." << std::endl;
        }
    }

    std::cout << "Redis Connection is successfull" << std::endl;

    signal(SIGPIPE, SIG_IGN);

    Main::listeners.emplace_back(80);  // HTTP
    Main::listeners.emplace_back(443); // HTTPS

    Main::resolverIp = Main::dotenv->map["resolver_ip"].data();

    Main::cas = new Cassandra();

    if (Main::cas->connect())
    {
        std::cout << "ScyllaDB Connected" << std::endl;
    }

    Origin::getSSLCerts();

    Core core;
    core.start();
}