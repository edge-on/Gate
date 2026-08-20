#pragma once

#include <liburing.h>
#include <stdio.h>

#include <iostream>

#include "Core/Gen/Gen.hpp"

namespace Utils
{
    class Uring
    {
    public:
        static struct io_uring_sqe *getSqe(struct io_uring *ring);

        static void makeNonBlocking(int fd);
        static void closeConn(int thread, Gen::Connection &conn);
        static void closeConnectionFull(int thread, int fd);
    };
} // namespace Utils
