#include <vector>
#include "elfio/elfio.hpp"

struct LoadError : public std::runtime_error
{
	LoadError(std::string const &message) : std::runtime_error(message) { }
};

void copyElfData(ELFIO::elfio &dest, ELFIO::elfio &src);
ELFIO::elfio newFromTemplate(ELFIO::elfio &templ, ELFIO::Elf64_Addr orEntry=0);
ELFIO::elfio loadElf(const std::string &input);
std::vector<ELFIO::elfio> loadElves(std::vector<std::string> &filenames);
