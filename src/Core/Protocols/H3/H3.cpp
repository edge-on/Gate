#include "Core/Protocols/H3/H3.hpp"

int Protocols::H3::run(struct io_uring_cqe *cqe, struct io_uring *ring, int thread, Pipeline::H3 *pipeline, SSL_CTX *ctx)
{
    std::cout << "I TAKE FROM UDP" << std::endl;

    uint64_t data = (uint64_t)io_uring_cqe_get_data(cqe);
    int fd = (int)(data & 0xFFFFFFFF);
    int opType = (int)(data >> 32);

    int res = cqe->res;
    bool hasMore = cqe->flags & IORING_CQE_F_MORE;
    io_uring_cqe_seen(ring, cqe);

    if (res < 0)
    {
        std::cout << "Res is minus! " << res << std::endl;
        return Gen::CONTINUE;
    }

    switch (opType)
    {
    case ::H3::Gen::H3_STATE_READ_CLIENT:
    {
        if (res <= 0)
            break;

        std::cout << "I recv from client " << res << " bytes!" << std::endl;

        uint32_t version;
        // quiche_header_info((uint8_t*)ref.buffer, ref.len, LOCAL_CONN_ID_LEN, &version, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

        std::cout << "Version " << version << std::endl;

        break;
    }
    }
}