#include "Core/Gen/Gen.hpp"

std::vector<std::thread> Gen::threads;
std::unordered_map<int, Gen::Thread> Gen::activeThreads;

std::unordered_map<std::string, Gen::Zone> Gen::zones;