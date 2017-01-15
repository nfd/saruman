# Saruman: ELF manipulation suite

Saruman is a set of three tools for manipulating and viewing ELF files. They are designed to work together in a pipeline.

## Building

    cmake .
	make -j

## The tools

*objcat* combines ELF files by creating a new file with all combined loadable segments of its inputs.

    objcat kernel.elf sigma0.elf >combined.elf

*objinfo* writes select information about the ELF file to stdout. It can currently display the entry point (-E) and the value of a given symbol (-V symbolname).

    objinfo -E combined.elf

*objpatch* writes arbitrary bytes to an ELF file at the virtual address you specify. In other words, if you wish to patch the 4 bytes which will be loaded at vaddr 0x80000c00, you could use it like so:

    objpatch -V 0x80000c00=u32:0x4000 <in.elf >out.elf

The above command patches the 32-bit unsigned integer which would be loaded at 0x80000c00 to be 0x4000.

