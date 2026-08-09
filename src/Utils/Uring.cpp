#include "Utils/Uring.hpp"

struct io_uring_sqe *Utils::Uring::getSqe(struct io_uring *ring)
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

void Utils::Uring::makeNonBlocking(int fd)
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

void Utils::Uring::closeConn(int thread, Gen::Connection &conn)
{
    auto sslIt = Gen::activeThreads[thread].ssl.find(conn.fd);
    if (sslIt != Gen::activeThreads[thread].ssl.end())
    {
        if (sslIt->second.ssl)
            SSL_free(sslIt->second.ssl);
        Gen::activeThreads[thread].ssl.erase(sslIt);
    }

    int fd = conn.fd;
    close(fd);
    Gen::activeThreads[thread].connections.erase(fd);
}