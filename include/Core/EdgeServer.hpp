#include <sys/epoll.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <iostream>
#include <vector>
#include <thread>
#include <chrono>
#include <openssl/ssl.h>
#include <unordered_map>

class EdgeServer
{
public:
    EdgeServer();
    
    EdgeServer& setPort(int PORT);

    void start();
    
    void initClientServer();
    void initBackendServer();

    void initSSL();

    enum ConnType {
        BACKEND,
        CLIENT
    };

    struct Connection
    {
        int fd;
        SSL* ssl;
        bool handshake_done;

        ConnType type;
    };
    
    std::unordered_map<int, Connection> connections;

private:
    int client_port = 8080;
    int backend_port = 9000;

    int MAX_EVENTS = 10;

    int client_listen, backend_listen;

    SSL_CTX* ctx;

    int handleBackend(Connection conn);
    int handleClient(Connection conn);

    void startWorkers();

    int makeNonBlocking(int sfd);
};