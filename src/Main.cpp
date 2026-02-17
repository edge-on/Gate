#include "Main.hpp"

int main(int argc, char *argv[]) {
    signal(SIGPIPE, SIG_IGN);

    Atlas* atlas = new Atlas();

    EdgeServer *e = new EdgeServer();
    e->start();
}