#include "Utils/Uring/H1/H1.hpp"

struct io_uring_sqe *Utils::H1::Uring::getSqe(struct io_uring *ring)
{
    if (!ring)
        return nullptr;

    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    if (!sqe)
    {
        io_uring_submit(ring);
        sqe = io_uring_get_sqe(ring);
    }

    return sqe;
}

void Utils::H1::Uring::makeNonBlocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1)
    {
        perror("fcntl F_GETFL");
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1)
    {
        perror("fcntl F_SETFL");
    }
}

void Utils::H1::Uring::closeConn(int thread, Gen::H1::H1Connection &conn)
{
    auto sslIt = Gen::Global::activeThreads[thread].ssl.find(conn.fd);
    if (sslIt != Gen::Global::activeThreads[thread].ssl.end())
    {
        if (sslIt->second.ssl)
            SSL_free(sslIt->second.ssl);
        Gen::Global::activeThreads[thread].ssl.erase(sslIt);
    }

    if (conn.type == Gen::Global::TYPE_CLIENT && Gen::Global::activeThreads[thread].activeConnections > 0)
        Gen::Global::activeThreads[thread].activeConnections--;

    int fd = conn.fd;
    close(fd);
    Gen::Global::activeThreads[thread].connections.erase(fd);
}

void Utils::H1::Uring::closeConnectionFull(int thread, int fd)
{
    auto it = Gen::Global::activeThreads[thread].connections.find(fd);
    if (it == Gen::Global::activeThreads[thread].connections.end())
        return;

    Gen::H1::H1Connection &conn = it->second;
    int peerFd = conn.peerFd;

    if (conn.resolverFd != -1)
    {
        close(conn.resolverFd);
        conn.resolverFd = -1;
    }

    if (peerFd != -1)
    {
        auto peerIt = Gen::Global::activeThreads[thread].connections.find(peerFd);
        if (peerIt != Gen::Global::activeThreads[thread].connections.end())
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