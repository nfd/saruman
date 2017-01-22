#include <vector>
#include <string>
#include <iostream>
#include <algorithm>
#include <tclap/CmdLine.h>
#include <inttypes.h>

#include "elfio/elfio.hpp"
#include "common.hpp"

#define VERSION "0.1"

static const ELFIO::Elf64_Addr MipsK0 = 0x80000000;
static const ELFIO::Elf64_Addr MipsK1 = 0xa0000000;

struct Args {
	std::string command;
	std::vector<std::string> inputs;
	bool mipsToK0;
	bool mipsToK1;

	static Args parse(int argc, char **argv){
		Args args;

		TCLAP::CmdLine cmdLine("elf concatenator", ' ', VERSION);
		TCLAP::SwitchArg mipsToK0Arg("0", "to-kseg0", "Convert VMAs to kseg0 (MIPS)", cmdLine);
		TCLAP::SwitchArg mipsToK1Arg("1", "to-kseg1", "Convert VMAs to kseg1 (MIPS)", cmdLine);
		TCLAP::UnlabeledMultiArg<std::string> inputArg("inputs", "Input file names", false, "filenames", cmdLine);

		cmdLine.parse(argc, argv);

		args.inputs = inputArg.getValue();
		args.mipsToK0 = mipsToK0Arg.getValue();
		args.mipsToK1 = mipsToK1Arg.getValue();

		return args;
	}
};

std::string inventSectionName(const std::string &filename, int segmentIdx, ELFIO::Elf_Word segmentFlags, ELFIO::Elf_Xword fileSize)
{
	size_t slashIdx = filename.rfind("/");
	std::string filenamePart(slashIdx == std::string::npos ? filename : filename.substr(slashIdx + 1));
	std::stringstream name;

	const char *usageGuess = fileSize == 0? "bss" : segmentFlags & PF_X ? "text" : "data";

	name << '.' << filenamePart << '.' << segmentIdx << '.' << usageGuess;
	return name.str();
}

ELFIO::Elf_Xword inventSectionFlags(ELFIO::Elf_Word segmentFlags)
{
	ELFIO::Elf_Xword flags = SHF_ALLOC;

	if(segmentFlags & PF_X)
		flags |= SHF_EXECINSTR;

	if(segmentFlags & PF_W)
		flags |= SHF_WRITE;

	return flags;
}

ELFIO::elfio mergeSegments(std::vector<ELFIO::elfio> &inputElves, ELFIO::Elf64_Addr orVma)
{
	auto elfOutput = newFromTemplate(inputElves[0], orVma);

	for(auto &elf : inputElves) {

		for(auto segment: elf.segments) {
			if(segment->get_type() == PT_LOAD && segment->get_memory_size() != 0) {
				auto segmentFlags = segment->get_flags();
				auto segmentFileSize = segment->get_file_size();
				auto segmentMemorySize = segment->get_memory_size();

				auto sectionName = inventSectionName(elf.get_name(), segment->get_index(), segmentFlags, segmentFileSize);

				auto vaddr = segment->get_virtual_address();
				vaddr |= orVma;

				// std::cout << "memory size " << segment->get_memory_size() << "\n";
				auto newSection = elfOutput.sections.add(sectionName);
				newSection->set_type(segmentFileSize == 0 ? SHT_NOBITS : SHT_PROGBITS);
				newSection->set_flags(inventSectionFlags(segmentFlags));
				newSection->set_addr_align(4); // TODO
				newSection->set_data(segment->get_data(), segmentFileSize);
				newSection->set_size(segmentMemorySize);
				newSection->set_address(vaddr);

				auto newSegment = elfOutput.segments.add();

				newSegment->set_type(segment->get_type());
				newSegment->set_flags(segment->get_flags());
				newSegment->set_align(segment->get_align());
				newSegment->set_virtual_address(vaddr);
				newSegment->set_physical_address(segment->get_physical_address());
				newSegment->add_section_index(newSection->get_index(), newSection->get_addr_align());

			}
		}
	}

	return elfOutput;
}

int main(int argc, char **argv)
{
	try {
		Args args = Args::parse(argc, argv);
		ELFIO::Elf64_Addr orVma = args.mipsToK0 ? MipsK0 : (args.mipsToK1 ? MipsK1 : 0);

		auto inputs = loadElves(args.inputs);
		auto output = mergeSegments(inputs, orVma);
		output.save("-");
	} catch (TCLAP::ArgException &e) {
		std::cerr << "error: " << e.error() << " for arg " << e.argId() << std::endl;
		return 1;
	} catch (LoadError &e) {
		std::cerr << "error: " << e.what() << "\n";
		return 1;
	}

	return 0;
}

