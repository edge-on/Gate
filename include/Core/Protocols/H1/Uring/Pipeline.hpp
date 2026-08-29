#pragma once

#include <liburing.h>
#include <iostream>

#include "Core/Gen/Gen.hpp"
#include "Utils/Uring/H1/H1.hpp"
#include "Utils/Pages.hpp"

namespace Pipeline
{
    class H1
    {
    public:
        H1(struct io_uring *ring, int thread);

        void queueMultishotAccept(int serverFd);

        void queueTlsConnecting(Gen::H1::H1Connection &conn);
        void queueReadClient(Gen::H1::H1Connection &conn);
        void queueWriteClient(Gen::H1::H1Connection &conn);

        void queueConnectOrigin(Gen::H1::H1Connection &originConn);
        void queueWriteOrigin(Gen::H1::H1Connection &conn);
        void queueReadOrigin(Gen::H1::H1Connection &conn);

        void queueConnectResolver(Gen::H1::H1Connection &conn, char* ip);
        void queueWriteResolver(Gen::H1::H1Connection &conn);
        void queueReadResolver(Gen::H1::H1Connection &conn);

        void writePage(Gen::H1::H1Connection &conn, std::string page);

    private:
        struct io_uring *ring;
        int thread;
    };
}