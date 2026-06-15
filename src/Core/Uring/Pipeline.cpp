#include "Core/Uring/Pipeline.hpp"

Pipeline::Pipeline(struct io_uring *ring, int thread)
{
    this->ring = ring;
    this->thread = thread;
}

void Pipeline::queueMultishotAccept(int serverFd)
{
}

void Pipeline::queueReadClient(Gen::Connection &conn)
{
}

void Pipeline::queueWriteClient(Gen::Connection &conn)
{
}

void Pipeline::queuePollAdd(Gen::Connection &conn)
{
}