#include "Core/Gen/H1/Gen.hpp"

std::vector<std::thread> Gen::H1::threads;
std::unordered_map<int, Gen::H1::Thread> Gen::H1::activeThreads;

ZoneMap Gen::H1::zones;