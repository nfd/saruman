#include <vector>
#include <string>
#include <iostream>
#include <algorithm>
#include <tclap/CmdLine.h>
#include <inttypes.h>

#include "elfio/elfio.hpp"
#include "common.hpp"

#define VERSION "0.1"

const std::string MagicSigma0InfoStructName = "sigma0_info";

static const ELFIO::Elf64_Addr MipsKernelSpace = 0x80000000;

/*
 * First cut at this: combine LOAD segments from both ELF files into one. Do
 * not translate VMAs.
 *
 * load infile append infile write outfile
*/

/* Must match kernel/sigma0_interface.c */
struct sigma0_info_struct32 {
	uint32_t entrypoint;
};

struct Args {
	int roundToPage;
	bool mips0to1;
	bool mips1to0;
	bool printHighestVaddr;
	bool printEntry;
	std::string printSymbolValue;
	std::string input;

	static Args parse(int argc, char **argv){
		Args args;

		TCLAP::CmdLine cmdLine("object info printer", ' ', VERSION);
		TCLAP::ValueArg<int> roundToPageArg("r", "round-to-page", "Round output up", false, 0, "bytes", cmdLine);
		TCLAP::SwitchArg printHighestVaddrArg("V", "highest-vaddr", "Display highest vaddr", cmdLine);
		TCLAP::SwitchArg printEntryArg("E", "entrypoint", "Display entrypoint", cmdLine);
		TCLAP::ValueArg<std::string> printSymbolValueArg("S", "symbol-value", "Display symbol value", false, "", "sym", cmdLine);
		TCLAP::SwitchArg mipsUserToKernelArg("1", "to-kseg0", "Convert MIPS VMAs to kseg1", cmdLine);
		TCLAP::SwitchArg mipsKernelToUserArg("0", "to-kuseg", "Convert MIPS VMAs to kuseg", cmdLine);
		TCLAP::UnlabeledValueArg<std::string> inputArg("input", "Input (default stdin)", false, "-", "filename", cmdLine);

		cmdLine.parse(argc, argv);

		args.printHighestVaddr = printHighestVaddrArg.getValue();
		args.printEntry = printEntryArg.getValue();
		args.printSymbolValue = printSymbolValueArg.getValue();
		args.roundToPage = roundToPageArg.getValue();
		args.mips0to1 = mipsUserToKernelArg.getValue();
		args.mips1to0 = mipsKernelToUserArg.getValue();
		args.input = inputArg.getValue();

		return args;
	}
};

static ELFIO::Elf64_Addr mips0To1(ELFIO::Elf64_Addr addr)
{
	return addr | MipsKernelSpace;
}

static ELFIO::Elf64_Addr mips1To0(ELFIO::Elf64_Addr addr)
{
	return addr & (~MipsKernelSpace);
}

ELFIO::Elf64_Addr findHighestVaddr(ELFIO::elfio &elf)
{
	ELFIO::Elf64_Addr highest = 0;

	for(auto phdr : elf.segments) {
		if(phdr->get_type() == PT_LOAD) {
			ELFIO::Elf64_Addr current = phdr->get_virtual_address() + phdr->get_memory_size();
			highest = std::max(highest, current);
		}
	}

	return highest;
}

#define PAGE_SIZE 4096
ELFIO::Elf64_Addr convertVma(ELFIO::Elf64_Addr vma, Args &args)
{
	if(args.mips1to0)
		vma = mips1To0(vma);
	else if (args.mips0to1)
		vma = mips0To1(vma);

	if(args.roundToPage && (vma & (args.roundToPage - 1))) {
		vma = (vma & (~(args.roundToPage - 1))) + args.roundToPage;
	}
	
	return vma;
}

ELFIO::section *getSymbolTable(ELFIO::elfio &elf)
{
	for(auto section : elf.sections) {
		if(section->get_type() == SHT_SYMTAB)
			return section;
	}
	return nullptr;
}

bool findSymbolForName(ELFIO::symbol_section_accessor syms, ELFIO::Elf64_Addr &value, ELFIO::Elf_Half &section_index, std::string &name)
{
	ELFIO::Elf_Xword size;
	unsigned char bind;
	unsigned char type;
	unsigned char other;
	std::string candidateName;

	ELFIO::Elf_Xword numSymbols = syms.get_symbols_num();
	for(ELFIO::Elf_Xword i = 0; i < numSymbols; i++) {
		syms.get_symbol(i, candidateName, value, size, bind, type, section_index, other);
		if(candidateName == name) {
			return true;
		}
	}

	return false;
}

bool findSymbolValue(ELFIO::elfio &elf, std::string &name, ELFIO::Elf64_Addr &value)
{
	ELFIO::section *symtab = getSymbolTable(elf);
	if(symtab == nullptr) {
		std::cerr << "no symtab in kernel elf\n";
		return false;
	}

	ELFIO::symbol_section_accessor syms(elf, symtab);
	ELFIO::Elf_Half section_index;
	
	return findSymbolForName(syms, value, section_index, name);
}

int main(int argc, char **argv)
{
	try {
		Args args = Args::parse(argc, argv);
		auto input = loadElf(args.input);

		if(args.printHighestVaddr) {
			ELFIO::Elf64_Addr vaddr = convertVma(findHighestVaddr(input), args);
			std::cout << "0x" << std::hex << vaddr << std::dec << '\n';
		}
		if(args.printSymbolValue != "") {
			ELFIO::Elf64_Addr value;
			if(findSymbolValue(input, args.printSymbolValue, value)) {
				std::cout << "0x" << std::hex << value << std::dec << "\n";
			} else {
				std::cerr << "No symbol named " << args.printSymbolValue << " found.\n";
			}
		}
		if(args.printEntry) {
			std::cout << "0x" << std::hex << input.get_entry() << std::dec << "\n";
		}

	} catch (TCLAP::ArgException &e) {
		std::cerr << "error: " << e.error() << " for arg " << e.argId() << std::endl;
		return 1;
	}

	return 0;
}

