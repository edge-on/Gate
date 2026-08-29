#include "Core/Gen/Gen.hpp"

std::vector<std::thread> Gen::Global::threads;
std::unordered_map<int, Gen::Global::Thread> Gen::Global::activeThreads;

ZoneMap Gen::Global::zones;