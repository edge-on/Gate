#include "Utils/Pages.hpp"

std::string Pages::getPage(std::string page)
{
    std::ifstream file(page);

    if (!file.is_open())
    {
        return "";
    }

    std::stringstream buffer;
    buffer << file.rdbuf();

    return buffer.str();
}