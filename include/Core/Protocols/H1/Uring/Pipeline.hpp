#pragma once

#include <liburing.h>
#include <iostream>

#include "Core/Gen/Gen.hpp"
#include "Utils/Uring/Uring.hpp"
#include "Utils/Pages.hpp"

namespace Pipeline
{
    class H1
    {
    public:
        H1(struct io_uring *ring, int thread);

        void queueMultishotAccept(int serverFd);

        void queueTlsConnecting(::H1::Gen::H1Connection &conn);
        void queueReadClient(::H1::Gen::H1Connection &conn);
        void queueWriteClient(::H1::Gen::H1Connection &conn);

        void queueConnectOrigin(::H1::Gen::H1Connection &originConn);
        void queueWriteOrigin(::H1::Gen::H1Connection &conn);
        void queueReadOrigin(::H1::Gen::H1Connection &conn);

        void queueConnectResolver(::H1::Gen::H1Connection &conn, char* ip);
        void queueWriteResolver(::H1::Gen::H1Connection &conn);
        void queueReadResolver(::H1::Gen::H1Connection &conn);

        void writePage(::H1::Gen::H1Connection &conn, std::string page);

    private:
        struct io_uring *ring;
        int thread;
    };
}