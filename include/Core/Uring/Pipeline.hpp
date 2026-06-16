#pragma once

#include <liburing.h>

#include "Core/Gen/Gen.hpp"

#include "Utils/Uring.hpp"

#include <iostream>

class Pipeline
{
public:
    Pipeline(struct io_uring *ring, int thread);

    void queueMultishotAccept(int serverFd);

    void queueReadClient(Gen::Connection &conn);
    void queueWriteOrigin(Gen::Connection &conn);
    void queueReadOrigin(Gen::Connection &conn);
    void queueWriteClient(Gen::Connection &conn);

    void queuePollAdd(Gen::Connection &conn);

private:
    struct io_uring *ring;
    int thread;
};