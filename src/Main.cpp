#include "Main.hpp"

Dotenv *Main::dotenv;

int main(int argc, char *argv[])
{
    Main::dotenv = new Dotenv();
    Main::dotenv->config(".env");

    signal(SIGPIPE, SIG_IGN);

    Main::listeners.emplace_back(80);  // HTTP
    Main::listeners.emplace_back(443); // HTTPS

    Core core;
    core.start();
}