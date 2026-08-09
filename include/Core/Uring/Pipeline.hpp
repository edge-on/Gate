#pragma once

#include <liburing.h>
#include <iostream>

#include "Main.hpp"
#include "Core/Gen/Gen.hpp"
#include "Utils/Uring.hpp"

class Pipeline
{
public:
    Pipeline(struct io_uring *ring, int thread);

    void queueMultishotAccept(int serverFd);

    void queueTlsConnecting(Gen::Connection &conn);
    void queueReadClient(Gen::Connection &conn);
    void queueWriteClient(Gen::Connection &conn);

    void queueConnectOrigin(Gen::Connection &originConn);
    void queueWriteOrigin(Gen::Connection &conn);
    void queueReadOrigin(Gen::Connection &conn);

    void queueConnectResolver(Gen::Connection &conn);
    void queueWriteResolver(Gen::Connection &conn, char packet[512]);
    void queueReadResolver(Gen::Connection &conn);

    void write502Page(Gen::Connection &conn);

private:
    struct io_uring *ring;
    int thread;
};