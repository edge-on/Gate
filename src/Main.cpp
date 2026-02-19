#include "Main.hpp"

int main(int argc, char *argv[]) {
    signal(SIGPIPE, SIG_IGN);

    cass_log_set_level(CASS_LOG_DISABLED);

    Atlas* atlas = new Atlas();

    EdgeServer *e = new EdgeServer();
    e->start();
}