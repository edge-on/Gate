#pragma once

#include <netinet/tcp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include <stdio.h>

#include "Utils/Uring/H1/H1.hpp"
#include "Utils/Uring/H3/H3.hpp"
#include "Utils/Uring/Uring.hpp"

namespace Transports
{
    class Proxy
    {
    public:
        static int initServer(int port /* in */);
        static int initUdpServer(int port /* in */);

        static int createOriginSocket(char *ip /* in */, int port /* in */, sockaddr_in &outAddr /* in */);
        static int createResolverSocket();
    };
}