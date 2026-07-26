#include "Main.hpp"

Dotenv *Main::dotenv;
DNSClient *Main::dns;
Cassandra *Main::cas;

std::vector<int> Main::listeners;

int main(int argc, char *argv[])
{
    Main::dotenv = new Dotenv();
    Main::dotenv->config(".env");

    Main::dns = new DNSClient("13.140.157.112", 53);

    signal(SIGPIPE, SIG_IGN);

    Main::listeners.emplace_back(80);  // HTTP
    Main::listeners.emplace_back(443); // HTTPS

    Main::cas = new Cassandra();

    if (Main::cas->connect())
    {
        std::cout << "ScyllaDB Connected" << std::endl;
    }

    Origin::getSSLCerts();

    Core core;
    core.start();
}