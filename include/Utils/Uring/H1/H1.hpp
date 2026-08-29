#pragma once

#include <liburing.h>
#include <stdio.h>

#include <iostream>

#include "Core/Gen/Gen.hpp"

namespace Utils
{
    namespace H1
    {
        class Uring
        {
        public:
            static struct io_uring_sqe *getSqe(struct io_uring *ring);

            static void makeNonBlocking(int fd);
            static void closeConn(int thread, Gen::H1::H1Connection &conn);
            static void closeConnectionFull(int thread, int fd);
        };
    }
} // namespace Utils
