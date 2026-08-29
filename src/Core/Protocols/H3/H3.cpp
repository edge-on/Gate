#include "Core/Protocols/H3/H3.hpp"

int Protocols::H3::run(struct io_uring_cqe *cqe, struct io_uring *ring, int thread, Pipeline::H3 *pipeline, SSL_CTX *ctx)
{
    uint64_t data = (uint64_t)io_uring_cqe_get_data(cqe);
    int streamId = (int)(data & 0xFFFFFFFF);
    int opType = (int)(data >> 32);

    int res = cqe->res;
    bool hasMore = cqe->flags & IORING_CQE_F_MORE;
    io_uring_cqe_seen(ring, cqe);

    if (res < 0)
    {
    }

    switch (opType)
    {
    case Gen::H3::H3_STATE_READ_CLIENT:
    {
        if (res <= 0)
            break;

        // SSL_CTX *ctx = quiche_config_get_ssl_ctx();
        // quiche_conn_recv(nullptr, )

        break;
    }
    }
}