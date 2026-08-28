#include "Core/Protocols/H3/Uring/Pipeline.hpp"

Pipeline::H3::H3(struct io_uring *ring, int thread)
{
    this->ring = ring;
    this->thread = thread;
}

void Pipeline::H3::queueReadClient()
{
}

void Pipeline::H3::queueWriteClient()
{
}

void Pipeline::H3::queueReadOrigin()
{
}

void Pipeline::H3::queueWriteOrigin()
{
}