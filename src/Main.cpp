#include "Core/EdgeServer.hpp"

int main(int argc, char *argv[]) {
    EdgeServer *e = new EdgeServer();

    e->start();
}