#include <cassert>

#include "common.hpp"

void copyElfData(ELFIO::elfio &dest, ELFIO::elfio &src)
{
	dest.sections.duplicate(src.sections);

	for(auto segment: src.segments) {
		auto newSegment = dest.segments.add();
		newSegment->set_type(segment->get_type());
		newSegment->set_flags(segment->get_flags());
		newSegment->set_align(segment->get_align());
		newSegment->set_physical_address(segment->get_physical_address());
		newSegment->set_virtual_address(segment->get_virtual_address());
		newSegment->set_file_size(segment->get_file_size());
		newSegment->set_memory_size(segment->get_memory_size());

		for(int i = 0; i < segment->get_sections_num(); i++) {
			int idx = segment->get_section_index_at(i);
			assert(idx > 0);

			newSegment->add_section_index(idx, segment->get_align());
		}
	}
}

ELFIO::elfio newFromTemplate(ELFIO::elfio &templ, ELFIO::Elf64_Addr orEntry)
{
	ELFIO::elfio elf;

	elf.create(templ.get_class(), templ.get_encoding());
	elf.set_os_abi(templ.get_os_abi());
	elf.set_abi_version(templ.get_abi_version());
	elf.set_type(templ.get_type());
	elf.set_machine(templ.get_machine());
	elf.set_flags(templ.get_flags());

	elf.set_entry(templ.get_entry() | orEntry);

	return elf;
}

ELFIO::elfio loadElf(const std::string &input)
{
	ELFIO::elfio elf;
	bool loaded;

	if(input == "-")
		loaded = elf.load_nonseekable(std::cin);
	else
		loaded = elf.load(input);

	if(!loaded) {
		throw LoadError("Failed to load " + input);
	}

	return elf;
}

std::vector<ELFIO::elfio> loadElves(std::vector<std::string> &filenames) {
	std::vector<ELFIO::elfio> elves;

	if(filenames.size() == 0) {
		/* We want at least one input, so read from stdin. */
		elves.push_back(std::move(loadElf("-")));
	} else {
		for(auto filename: filenames) {
			elves.push_back(std::move(loadElf(filename)));
		}
	}

	return elves;
}

