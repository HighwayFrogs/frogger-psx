/*
This linker script is part of the effort to use the GNU toolchain (modern Linux tools) as a replacement for the PsyQ tools / toolchain.
This script allows mipsel-linux-gnu-ld to replace PSYLINK.EXE / SLINK.EXE by recreating roughly how the original linker worked.
This script likely works with other games, but may need modification.


Obtained from: https://github.com/grumpycoders/pcsx-redux/blob/main/src/mips/ps-exe.ld
Modified by Kneesnap & nicolasnoble to mimick PsyQ build toolchain. (THANK YOU, this was my first time using LD)
Documentation: https://sourceware.org/binutils/docs/ld/Builtin-Functions.html
Documentation: https://sourceware.org/binutils/docs/ld/Output-Section-Data.html
Documentation: https://ftp.gnu.org/old-gnu/Manuals/gas-2.9.1/html_chapter/as_7.html

TODO:
 1) Build nearly matching executable
  - matching maspsx
  - bss section ordering hashing? single .comm?
  - 
 2) Bring back ctors?
 3) Modern GCC compatibility?
 4) Make this general 'psyq.ld'
*/

/*

MIT License

Copyright (c) 2019 PCSX-Redux authors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/

OUTPUT_FORMAT("binary")

EXTERN(__SN_ENTRY_POINT)
ENTRY(__SN_ENTRY_POINT)

TLOAD_ADDR = DEFINED(TLOAD_ADDR) ? TLOAD_ADDR : 0x80010000;

MEMORY {
    loader      : ORIGIN = (TLOAD_ADDR - 0x800), LENGTH = 2048
    ram (rwx)   : ORIGIN = TLOAD_ADDR, LENGTH = 2M - (TLOAD_ADDR - 0x80000000)
    dcache      : ORIGIN = 0x1f800000, LENGTH = 0x400
}

_gp             = __sdata_start;
__ram_top       = ORIGIN(ram) + LENGTH(ram);
__sp            = __ram_top - 0x10;

__dcache        = ORIGIN(dcache);
__dcache_top    = ORIGIN(dcache) + LENGTH(dcache);

__ftext_len     = (__ftext_end - __ftext_start);
__fdata_len     = (__fdata_end - __fdata_start);
__fbss_len      = (__fbss_end - __fbss_start);

__text_len      = (__text_end - __text_start);
__data_len      = (__data_end - __data_start);
__sbss_len      = (__sbss_end - __sbss_start);
__bss_len       = (__bss_end - __bss_start);

__stack_start   = ORIGIN(ram) + LENGTH(ram);

SECTIONS {
    .PSX_EXE_Header : {
        /*
            0x0000 - 0x0007 : "PS-X EXE"
        */
        BYTE(80); BYTE(83); BYTE(45); BYTE(88); BYTE(32); BYTE(69); BYTE(88); BYTE(69);

        /* 0x0008 - 0x000F : skip text_off and data_off since they're not supported by the PS1 BIOS */
        LONG(0); LONG(0);

        /* 0x0010 - 0x0013 : entry point */
        LONG(ABSOLUTE(__SN_ENTRY_POINT));

        /* 0x0014 - 0x0017 : initial value of $gp */
        LONG(0);

        /* 0x0018 - 0x001B : Memory address to load "text" section to. */
        /*
            NOTE: The "text" section is actually all of the "load"
            sections of the file including .text, .rodata, .data.
            etc.
        */
        LONG(TLOAD_ADDR);

        /* 0x001C - 0x001F :  size, in bytes, of the "text" section. */
        LONG(__ftext_len + __fdata_len);

        /* 0x0020 - 0x002F :
            Skip "data_addr", "data_size", "bss_addr" and "bss_size".
            None of these are supported by retail PS1 BIOS.
        */
        LONG(0); LONG(0);
        LONG(0); LONG(0);

        /* 0x0030 - 0x0033 :  Initial stack address. */
        LONG(DEFINED(_sp) ? ABSOLUTE(_sp) : 0x801FFFF0);

        /* 0x0034 - 0x0037 : Initial stack size, set it to 0. */
        LONG(0);

        /* 0x0038 - 0x004B : Empty. */
        LONG(0); LONG(0);
        LONG(0); LONG(0);
        LONG(0);

        /* 0x004C - 0x0083 "Sony Computer Entertainment Inc. for North America area" */
        BYTE(0x53); BYTE(0x6F); BYTE(0x6E); BYTE(0x79); BYTE(0x20); /* 'Sony ' */
		BYTE(0x43); BYTE(0x6F); BYTE(0x6D); BYTE(0x70); BYTE(0x75); BYTE(0x74); BYTE(0x65); BYTE(0x72); BYTE(0x20); /* 'Computer ' */
		BYTE(0x45); BYTE(0x6E); BYTE(0x74); BYTE(0x65); BYTE(0x72); BYTE(0x74); BYTE(0x61); BYTE(0x69); BYTE(0x6E); BYTE(0x6D); BYTE(0x65); BYTE(0x6E); BYTE(0x74); BYTE(0x20); /* 'Entertainment ' */
		BYTE(0x49); BYTE(0x6E); BYTE(0x63); BYTE(0x2E); BYTE(0x20); /* 'Inc. ' */
		BYTE(0x66); BYTE(0x6F); BYTE(0x72); BYTE(0x20); /* 'for ' */
		BYTE(0x4E); BYTE(0x6F); BYTE(0x72); BYTE(0x74); BYTE(0x68); BYTE(0x20); /* 'North ' */
		BYTE(0x41); BYTE(0x6D); BYTE(0x65); BYTE(0x72); BYTE(0x69); BYTE(0x63); BYTE(0x61); BYTE(0x20); /* 'America ' */
		BYTE(0x61); BYTE(0x72); BYTE(0x65); BYTE(0x61); BYTE(0); /* 'area' */

        /* Skip the remaining fields as they're not supported by the BIOS */
        /* e.g. 2048 header bytes minus whatever we've actually used */
        . = . + 1916;
    } > loader

    __text_start = .;
    __ftext_start = ABSOLUTE(.);
    .text TLOAD_ADDR : SUBALIGN(4) {
        *(.start)
        *(.init)
        KEEP (*(SORT_NONE(.fini)))
        *(.text.unlikely .text.*_unlikely .text.unlikely.*)
        *(.text.exit .text.exit.*)
        *(.text.startup .text.startup.*)
        *(.text.hot .text.hot.*)
        *(.text .stub .text.* .gnu.linkonce.t.*)

        . = ALIGN(16);
        KEEP(*(.init))
        . = ALIGN(16);
        KEEP(*(.fini))
    } > ram

    . = ALIGN(16);
    __text_end = .;
    __ftext_end = ABSOLUTE(.);

    __fdata_start = ABSOLUTE(.);

    .rodata : SUBALIGN(4) {
        *(.rodata .rodata.* .rdata .rdata.* .gnu.linkonce.r.*)
        . = ALIGN(16);
    } > ram

    . = ALIGN(16);
    __data_start = .;
    .data ALIGN(16) : SUBALIGN(4) {
        KEEP (*(.data .data.* .gnu.linkonce.d.*))
    } > ram
    __data_end = .;

    __sdata_start = .;
    .sdata : SUBALIGN(4) {
        KEEP (*(.sdata .sdata.* .gnu.linkonce.s.*))
        /* pad file to be a multiple of 2048 bytes.  Needed for loading from CD-ROM. */
        __sdata_end = .;
        . = ALIGN(2048);
    } > ram
    __fdata_end = .;

    . = __sdata_end;
    . = ALIGN(8);
    __fbss_start = .;
    __sbss_start = .;
    .sbss ALIGN(1) (NOLOAD) : SUBALIGN(8) {
        *(.dynsbss)
        *(.sbss .sbss.* .gnu.linkonce.sb.*)
        *(.scommon)
    } > ram

    . = ALIGN(8); /* TODO: THIS IS A HACK, IT SHOULD BE 4 */
    __sbss_end = .;
    
    __bss_start = .;
    .bss . (NOLOAD) : SUBALIGN(8) {
        *(.dynbss)
        *(.bss .bss.* .gnu.linkonce.b.*)
        *(COMMON)
    } > ram

    . = ALIGN(4);
    __bss_end = .;
    __fbss_end = .;

    . = ADDR(.text) - 0x800;
    __end = .;

    /DISCARD/ : { *(.MIPS.abiflags) }
    /DISCARD/ : { *(.reginfo) }

    /* Everything is statically linked, so discard PLTs. */
    /DISCARD/ : { *(.rel.iplt) *(.rela.iplt) *(.rel.plt) *(.rela.plt) *(.plt) *(.iplt) }

    /* Discard things that the standard link script drops, too. */
    /DISCARD/ : { *(.note.GNU-stack) *(.gnu_debuglink) *(.gnu.lto_*) }

    .scratchpad (NOLOAD) : {
        *(.scratchpad)
    } > dcache
}