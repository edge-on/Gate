#pragma once

#include <liburing.h>
#include <iostream>

#include "Core/Gen/Gen.hpp"
#include "Utils/Uring.hpp"
#include "Utils/Pages.hpp"

namespace Pipeline
{
    class H1
    {
    public:
        H1(struct io_uring *ring, int thread);

        void queueMultishotAccept(int serverFd);

        void queueTlsConnecting(Gen::Connection &conn);
        void queueReadClient(Gen::Connection &conn);
        void queueWriteClient(Gen::Connection &conn);

        void queueConnectOrigin(Gen::Connection &originConn);
        void queueWriteOrigin(Gen::Connection &conn);
        void queueReadOrigin(Gen::Connection &conn);

        void queueConnectResolver(Gen::Connection &conn, char* ip);
        void queueWriteResolver(Gen::Connection &conn);
        void queueReadResolver(Gen::Connection &conn);

        void writePage(Gen::Connection &conn, std::string page);

    private:
        struct io_uring *ring;
        int thread;
    };
}