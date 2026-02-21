#include "Utility/Epoll.hpp"

void EpollUtility::enableWrite(int fd, int epoll_fd)
{
    epoll_event ev{};
    ev.events = EPOLLIN | EPOLLOUT | EPOLLET;
    ev.data.fd = fd;

    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);
}

void EpollUtility::disableWrite(int fd, int epoll_fd)
{
    epoll_event ev{};
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = fd;

    epoll_ctl(epoll_fd, EPOLL_CTL_MOD, fd, &ev);
}

int EpollUtility::makeNonBlocking(int sfd)
{
    int flags = fcntl(sfd, F_GETFL, 0);
    if (flags == -1)
        return -1;
    flags |= O_NONBLOCK;
    return fcntl(sfd, F_SETFL, flags);
}