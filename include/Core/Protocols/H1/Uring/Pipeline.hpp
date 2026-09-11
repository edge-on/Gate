#pragma once

#include <liburing.h>
#include <iostream>
#include <cstdint>
#include <cstring>

#include "Core/Gen/Gen.hpp"
#include "Utils/Uring/Uring.hpp"
#include "Utils/Pages.hpp"

namespace Pipeline
{
    class H1
    {
    public:
        H1(struct io_uring *ring, int thread);

        void queueMultishotAccept(int serverFd /* in */);

        void queueTlsConnecting(::H1::Gen::H1Connection &conn /* in */);
        void queueReadClient(::H1::Gen::H1Connection &conn /* in */);
        void queueWriteClient(::H1::Gen::H1Connection &conn /* in */);

        void queueConnectOrigin(::H1::Gen::H1Connection &originConn /* in */);
        void queueWriteOrigin(::H1::Gen::H1Connection &conn /* in */);
        void queueReadOrigin(::H1::Gen::H1Connection &conn /* in */);

        void queueConnectResolver(::H1::Gen::H1Connection &conn /* in */, char* ip /* in */);
        void queueWriteResolver(::H1::Gen::H1Connection &conn /* in */);
        void queueReadResolver(::H1::Gen::H1Connection &conn /* in */);

        void writePage(::H1::Gen::H1Connection &conn /* in */, std::string page /* in */);

    private:
        struct io_uring *ring;
        int thread;
    };
}