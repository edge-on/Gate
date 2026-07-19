#include "Main.hpp"

Dotenv *Main::dotenv;
DNSClient *Main::dns;
Cassandra *Main::cas;

std::vector<int> Main::listeners;

int main(int argc, char *argv[])
{
    Main::dotenv = new Dotenv();
    Main::dotenv->config(".env");

    Main::dns = new DNSClient("127.0.0.1", 53);

    signal(SIGPIPE, SIG_IGN);

    Main::listeners.emplace_back(80);  // HTTP
    Main::listeners.emplace_back(443); // HTTPS

    Main::cas = new Cassandra();

    if (Main::cas->connect())
    {
        std::cout << "ScyllaDB Connected" << std::endl;
    }

    Core core;
    core.start();
}