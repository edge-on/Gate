#include "Main.hpp"

int main(int argc, char *argv[])
{
    Main::dotenv = new Dotenv();
    Main::dotenv->config(".env");

    signal(SIGPIPE, SIG_IGN);

    cass_log_set_level(CASS_LOG_DISABLED);

    Atlas *atlas = new Atlas();

    EdgeServer *e = new EdgeServer();
    e->start();
}