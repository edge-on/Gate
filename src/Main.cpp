#include "Main.hpp"

Dotenv *Main::dotenv;

int main(int argc, char *argv[])
{
    Main::dotenv = new Dotenv();
    Main::dotenv->config(".env");

    signal(SIGPIPE, SIG_IGN);

    Core core;
    core.start();
}