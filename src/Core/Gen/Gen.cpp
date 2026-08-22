#include "Core/Gen/Gen.hpp"

std::vector<std::thread> Gen::threads;
std::unordered_map<int, Gen::Thread> Gen::activeThreads;

ZoneMap Gen::zones;