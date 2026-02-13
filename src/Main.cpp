#include "Main.hpp"

#include "Core/EdgeServer.hpp"

int main(int argc, char *argv[]) {
    signal(SIGPIPE, SIG_IGN);

    EdgeServer *e = new EdgeServer();

    e->start();
}