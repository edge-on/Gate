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
            static void closeConn(int thread, ::H1::Gen::H1Connection &conn);
            static void closeConnectionFull(int thread, int fd);
        };
    }
} // namespace Utils
