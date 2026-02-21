#pragma once

#include <sys/epoll.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <unistd.h>

class EpollUtility {
public:
    static void enableWrite(int fd, int epoll_fd);
    static void disableWrite(int fd, int epoll_fd);

    static int makeNonBlocking(int sfd);
};