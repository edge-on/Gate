#include "Utils/Uring/H1/H1.hpp"

void Utils::H1::Uring::closeConn(int thread, ::H1::Gen::H1Connection &conn)
{
    auto sslIt = Gen::activeThreads[thread].ssl.find(conn.fd);
    if (sslIt != Gen::activeThreads[thread].ssl.end())
    {
        if (sslIt->second.ssl)
            SSL_free(sslIt->second.ssl);
        Gen::activeThreads[thread].ssl.erase(sslIt);
    }

    if (conn.type == Gen::TYPE_CLIENT && Gen::activeThreads[thread].activeConnections > 0)
        Gen::activeThreads[thread].activeConnections--;

    int fd = conn.fd;
    close(fd);
    Gen::activeThreads[thread].connections.erase(fd);
}

void Utils::H1::Uring::closeConnectionFull(int thread, int fd)
{
    auto it = Gen::activeThreads[thread].connections.find(fd);
    if (it == Gen::activeThreads[thread].connections.end())
        return;

    ::H1::Gen::H1Connection &conn = it->second;
    int peerFd = conn.peerFd;

    if (conn.resolverFd != -1)
    {
        close(conn.resolverFd);
        conn.resolverFd = -1;
    }

    if (peerFd != -1)
    {
        auto peerIt = Gen::activeThreads[thread].connections.find(peerFd);
        if (peerIt != Gen::activeThreads[thread].connections.end())
        {
            if (peerIt->second.resolverFd != -1)
            {
                close(peerIt->second.resolverFd);
                peerIt->second.resolverFd = -1;
            }
            peerIt->second.peerFd = -1;
            closeConn(thread, peerIt->second);
        }
        conn.peerFd = -1;
    }

    closeConn(thread, conn);
}