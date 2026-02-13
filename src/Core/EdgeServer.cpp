#include "Core/EdgeServer.hpp"

EdgeServer::EdgeServer()
{
}

EdgeServer &EdgeServer::setPort(int PORT)
{
    this->PORT = PORT;
    return *this;
}

void EdgeServer::start()
{
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == -1)
    {
        perror("socket");
    }

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(server_fd, (sockaddr *)&addr, sizeof(addr)) < 0)
    {
        perror("bind");
    }

    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    ctx = SSL_CTX_new(TLS_server_method());

    SSL_CTX_use_certificate_file(ctx, "a.pem", SSL_FILETYPE_PEM);
    SSL_CTX_use_PrivateKey_file(ctx, "c.pem", SSL_FILETYPE_PEM);

    if (listen(server_fd, SOMAXCONN) < 0)
    {
        perror("listen");
    }

    makeNonBlocking(server_fd);

    startWorker();
}

void EdgeServer::startWorker()
{
    int epoll_fd = epoll_create1(0);
    epoll_event event{};
    event.events = EPOLLIN | EPOLLOUT;
    event.data.fd = server_fd;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &event) < 0)
    {
        perror("epoll_ctl");
    }

    epoll_event events[MAX_EVENTS];

    while (true)
    {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);

        for (int i = 0; i < n; ++i)
        {
            if (events[i].data.fd == server_fd)
            {
                sockaddr_in client_addr{};
                socklen_t client_len = sizeof(client_addr);

                int client_fd = accept(server_fd, (sockaddr *)&client_addr, &client_len);
                if (client_fd == -1)
                    break;

                makeNonBlocking(client_fd);

                SSL *ssl = SSL_new(ctx);
                SSL_set_fd(ssl, client_fd);
                SSL_set_accept_state(ssl);

                Connection conn;
                conn.fd = client_fd;
                conn.ssl = ssl;
                conn.handshake_done = false;

                connections[client_fd] = conn;

                epoll_event client_event{};
                client_event.events = EPOLLIN | EPOLLET;
                client_event.data.fd = client_fd;
                epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &client_event);
            }
            else
            {
                auto &conn = connections[events[i].data.fd];

                if (!conn.handshake_done)
                {
                    int ret = SSL_accept(conn.ssl);

                    if (ret == 1)
                    {
                        conn.handshake_done = true;
                    }
                    else
                    {
                        int err = SSL_get_error(conn.ssl, ret);

                        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE)
                        {
                            continue;
                        }

                        SSL_free(conn.ssl);
                        close(conn.fd);

                        connections.erase(conn.fd);
                    }
                }
                else
                {
                    char buffer[4096];

                    int bytes = SSL_read(conn.ssl, buffer, sizeof(buffer));

                    if (bytes > 0)
                    {
                        std::string body = "Hello TLS World";

                        std::string response =
                            "HTTP/1.1 200 OK\r\n"
                            "Connection: keep-alive\r\n"
                            "Connection-Type: text/plain\r\n" +
                            ("Connection-Length: " + std::to_string(body.size()) + "\r\n") +
                            "\r\n" +
                            body;

                        SSL_write(conn.ssl, response.c_str(), response.size());
                    }
                    else
                    {
                        int err = SSL_get_error(conn.ssl, bytes);

                        if (err == SSL_ERROR_WANT_READ)
                        {
                            continue;
                        }

                        SSL_shutdown(conn.ssl);
                        SSL_free(conn.ssl);
                        close(conn.fd);

                        connections.erase(conn.fd);
                    }
                }
            }
        }
    }

    close(server_fd);
}

int EdgeServer::makeNonBlocking(int sfd)
{
    int flags = fcntl(sfd, F_GETFL, 0);
    if (flags == -1)
        return -1;
    flags |= O_NONBLOCK;
    return fcntl(sfd, F_SETFL, flags);
}