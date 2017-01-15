
#include <vector>
#include <string>
#include <iostream>
#include <algorithm>
#include <tclap/CmdLine.h>
#include <inttypes.h>

#include "elfio/elfio.hpp"
#include "common.hpp"

#define VERSION "0.1"

struct ParseError : public std::runtime_error {
	ParseError(std::string const &message) : std::runtime_error(message) { }
};

uint8_t parseNybble(char value) {
	if(value >= '0' && value <= '9')
		return value - '0';
	else if (value >= 'A' && value <= 'F')
		return 10 + (value - 'A');
	else if (value >= 'a' && value <= 'f')
		return 10 + (value - 'a');
	else
		throw ParseError("Unexpected value in hex string");
}

std::vector<uint8_t>parseBytes(const std::string &bytes_str)
{
	std::vector<uint8_t> bytes;

	size_t length = bytes_str.length();

	if(length % 2 != 0) {
		throw ParseError("Hex byte string not multiple of 2");
	}

	bool first = true;
	uint8_t current = 0;
	for(size_t idx = 0; idx < length; idx++) {
		current |= parseNybble(bytes_str[idx]);
		if(first) {
			current <<= 4; // shift one nybble up.
		} else {
			bytes.push_back(current);
			current = 0;
		}
		first = !first;
	}

	return bytes;
}

bool stringStartsWith(const std::string &haystack, const std::string &needle)
{
	/* Awful of c++ that I need to use boost or write this myself */
	size_t haystackSize = haystack.length(), needleSize = needle.length();
	size_t pos;

	for(pos = 0; pos < haystackSize && pos < needleSize; pos++) {
		if(haystack[pos] != needle[pos])
			return false;
	}

	return pos == needleSize;
}

struct Patch {
	enum PatchKind {RawBytes, Unsigned32};

	ELFIO::Elf64_Addr addr;
	PatchKind kind;

	uint32_t unsigned32;
	std::vector<uint8_t> bytes;


	Patch(std::string cmdline) {
		if(cmdline.length() == 0) {
			throw ParseError("No patch data specified");
		}
		size_t equals_pos = cmdline.find("=");
		if(equals_pos == std::string::npos) {
			throw ParseError("No = sign found (Format: vaddr=hex-bytes)");
		}

		addr = std::stoul(cmdline.substr(0, equals_pos), 0, 0);
		auto patchBytes = cmdline.substr(equals_pos + 1);

		if(patchBytes.length() == 0) {
			throw ParseError("No patch bytes");
		}

		if(stringStartsWith(patchBytes, "u32:")) {
			kind = Unsigned32;
			unsigned32 = std::stoul(patchBytes.substr(4), 0, 0);
		} else if (stringStartsWith(patchBytes, "hex:")) {
			kind = RawBytes;
			bytes = parseBytes(patchBytes.substr(4));
		} else {
			throw ParseError("Unknown patch kind. Use u32:0x... or hex:...\n");
		}
	}

	Patch(Patch &&rhs) {
		addr = rhs.addr;
		kind = rhs.kind;
		unsigned32 = rhs.unsigned32;
		bytes = std::move(rhs.bytes);
	}
};

std::vector<Patch>constructPatchList(const std::vector<std::string> &patchListArgs) {
	std::vector<Patch>patches;

	for(auto arg: patchListArgs) {
		patches.push_back(Patch(arg));
	}

	return patches;
}

struct Args {
	std::string input;
	std::string output;
	std::vector<Patch> patchVaddrs;

	static Args parse(int argc, char **argv){
		Args args;

		TCLAP::CmdLine cmdLine("object file patcher", ' ', VERSION);
		TCLAP::ValueArg<std::string> outputArg("o", "output", "Output file name", false, "-", "filename", cmdLine);
		TCLAP::MultiArg<std::string> patchVaddrArg("V", "patch-vaddr", "patch vaddr", false, "addr=patchspec", cmdLine);
		TCLAP::UnlabeledValueArg<std::string> inputArg("input", "Input (default stdin)", false, "-", "filename", cmdLine);

		cmdLine.parse(argc, argv);

		args.input = inputArg.getValue();
		args.output = outputArg.getValue();
		args.patchVaddrs = constructPatchList(patchVaddrArg.getValue());

		return args;
	}
};

void patchSectionData(ELFIO::section *section, off_t offset, uint8_t *bytes, size_t bytes_length)
{

	ELFIO::Elf_Xword section_size = section->get_size();
	uint8_t *patched = new uint8_t[section_size];
	const uint8_t *orig = (const uint8_t *)section->get_data();

	memcpy(patched, orig, section_size);
	memcpy(&patched[offset], bytes, bytes_length);

	section->set_data((const char *)patched, section_size);

	delete[] patched;
}

ELFIO::section *findSectionForVaddr(ELFIO::elfio &elf, ELFIO::Elf64_Addr vaddr)
{
	for(auto section : elf.sections) {
		if(section->get_type() == SHT_PROGBITS
				&& section->get_address() <= vaddr
				&& (section->get_address() + section->get_size()) > vaddr) {
			return section;
		}
	}
	return nullptr;
}

int patchVaddrs(ELFIO::elfio &elf, std::vector<Patch>&patchList)
{
	/* Elfio insists on us patching data in section rather than segment, so do things that way. */
	for(auto &patch: patchList) {
		ELFIO::section *section = findSectionForVaddr(elf, patch.addr);

		if(section == nullptr) {
			std::cerr << "Couldn't find containing section for patch data vaddr\n";
			return -1;
		}

		off_t offset = patch.addr - section->get_address();

		switch(patch.kind) {
			case Patch::RawBytes:
				patchSectionData(section, offset, patch.bytes.data(), patch.bytes.size());
				break;
			case Patch::Unsigned32: {
				/* TODO: endianness conversion (use endianness specified in ELF
				 * header and allow fallback to cmdline for multi endian systems) */
				patchSectionData(section, offset, (uint8_t *)(&patch.unsigned32), 4);
				break;
			}
			default:
				abort();
				break;
		} 
	}

	return 0;
}

ELFIO::elfio loadElf(std::string &input)
{
	/* Pretty nasty -- loading non-seekable streams requires creating a
	 * temporary copy first, which we only do if the input is stdin */
	ELFIO::elfio elf;

	if(input == "-") {
		elf.load_nonseekable(std::cin);
	} else {
		elf.load(input);
	}

	return elf;
}

int main(int argc, char **argv)
{
	try {
		Args args = Args::parse(argc, argv);

		auto input = loadElf(args.input);
		auto output = newFromTemplate(input);
		copyElfData(output, input);

		int retcode = 0;

		if(args.patchVaddrs.size()) {
			retcode |= patchVaddrs(output, args.patchVaddrs);
		}

		if(retcode == 0) {
			output.save(args.output);
		} else {
			std::cerr << "Patching failed\n";
		}

		return retcode;
	} catch (TCLAP::ArgException &e) {
		std::cerr << "error: " << e.error() << " for arg " << e.argId() << std::endl;
		return 1;
	}

	return 0;
}

