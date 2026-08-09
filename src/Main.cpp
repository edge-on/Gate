#include "Main.hpp"

Dotenv *Main::dotenv;
Cassandra *Main::cas;

std::vector<int> Main::listeners;

char *Main::resolverIp;

int main(int argc, char *argv[])
{
    Main::dotenv = new Dotenv();
    Main::dotenv->config(".env");

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