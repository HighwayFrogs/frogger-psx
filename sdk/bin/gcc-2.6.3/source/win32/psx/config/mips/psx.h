/* Definitions of target machine for GNU compiler.  PlayStation Version based on iris3.h.
   Copyright (C) 1991 Free Software Foundation, Inc.

This file is part of GNU CC.

GNU CC is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2, or (at your option)
any later version.

GNU CC is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with GNU CC; see the file COPYING.  If not, write to
the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.  */

/*  This file was modified from iris3.h by Martin Day, SN Systems Ltd
    January 1994, to build a little-endian compiler                    */

#define TARGET_DEFAULT (MASK_GAS+MASK_SOFT_FLOAT)

#define SGI_TARGET 1		/* inform other mips files this is SGI */

/* Names to predefine in the preprocessor for this target machine.  */

#define CPP_PREDEFINES	"-Dmips -DMIPSEL"

#define STARTFILE_SPEC	"%{pg:gcrt1.o%s}%{!pg:%{p:mcrt1.o%s}%{!p:crt1.o%s}}"

#define CPP_SPEC "\
%{!ansi:-D__EXTENSIONS__} -D_MIPSEL \
%{.S:	-D_LANGUAGE_ASSEMBLY %{!ansi:-DLANGUAGE_ASSEMBLY}} \
%{.s:	-D_LANGUAGE_ASSEMBLY %{!ansi:-DLANGUAGE_ASSEMBLY}} \
%{.cc:	-D_LANGUAGE_C_PLUS_PLUS} \
%{.cxx:	-D_LANGUAGE_C_PLUS_PLUS} \
%{.C:	-D_LANGUAGE_C_PLUS_PLUS} \
%{.m:	-D_LANGUAGE_OBJECTIVE_C} \
%{!.S: %{!.s: %{!.cc: %{!.cxx: %{!.C: %{!.m: -D_LANGUAGE_C %{!ansi:-DLANGUAGE_C}}}}}}} \
%{mlong64:-D__SIZE_TYPE__=long\\ unsigned\\ int -D__PTRDIFF_TYPE__=long\\ int} \
%{!mlong64:-D__SIZE_TYPE__=unsigned\\ int -D__PTRDIFF_TYPE__=int} \
%{mips3:-U__mips -D__mips=3}"

#define LIB_SPEC	\
	"%{!p:%{!pg:%{!static:%{!g*:-lc_s}} -lc}}%{p:-lc_p}%{pg:-lc_p} crtn.o%s"

#define MACHINE_TYPE	"Sony Playstation"

/* SGI Iris doesn't support -EB/-EL like other MIPS processors.  */

#define ASM_SPEC "\
%{!mgas: \
	%{!mrnames: %{!.s:-nocpp} %{.s: %{cpp} %{nocpp}}} \
	%{pipe: %e-pipe is not supported.} \
	%{mips1} %{mips2} %{mips3} \
	%{noasmopt:-O0} \
	%{!noasmopt:%{O:-O2} %{O1:-O2} %{O2:-O2} %{O3:-O3}} \
	%{g} %{g0} %{g1} %{g2} %{g3} %{v} %{K} \
	%{ggdb:-g} %{ggdb0:-g0} %{ggdb1:-g1} %{ggdb2:-g2} %{ggdb3:-g3} \
	%{gstabs:-g} %{gstabs0:-g0} %{gstabs1:-g1} %{gstabs2:-g2} %{gstabs3:-g3} \
	%{gstabs+:-g} %{gstabs+0:-g0} %{gstabs+1:-g1} %{gstabs+2:-g2} %{gstabs+3:-g3} \
	%{gcoff:-g} %{gstabs0:-g0} %{gcoff1:-g1} %{gcoff2:-g2} %{gcoff3:-g3}} \
%{G*}"

#define LINK_SPEC "\
%{G*} \
%{!mgas: %{mips1} %{mips2} %{mips3} \
	 %{bestGnum} %{shared} %{non_shared}}"

/* Always use 1 for .file number.  I [meissner@osf.org] wonder why
   IRIS needs this.  */

#define SET_FILE_NUMBER() num_source_filenames = 1

/* Put out a label after a .loc.  I [meissner@osf.org] wonder why
   IRIS needs this.  */

#define LABEL_AFTER_LOC(STREAM) fprintf (STREAM, "LM%d:\n", ++sym_lineno)

#define STACK_ARGS_ADJUST(SIZE)                                         \
{                                                                       \
  SIZE.constant += 4;                                                   \
  if (SIZE.constant < 32)						\
    SIZE.constant = 32;                                                 \
}

/* Define this macro to control use of the character `$' in
   identifier names.  The value should be 0, 1, or 2.  0 means `$'
   is not allowed by default; 1 means it is allowed by default if
   `-traditional' is used; 2 means it is allowed by default provided
   `-ansi' is not used.  1 is the default; there is no need to
   define this macro in that case. */

#define DOLLARS_IN_IDENTIFIERS 0

/* Tell G++ not to create constructors or destructors with $'s in them.  */

#define NO_DOLLAR_IN_LABEL 1

/* Specify wchar_t type.  */
#define WCHAR_TYPE	"unsigned char"
#define WCHAR_TYPE_SIZE BITS_PER_UNIT

/* Generate calls to memcpy, etc., not bcopy, etc.  */
#define TARGET_MEM_FUNCTIONS

/* Plain char is unsigned in the SGI compiler.  */
#define DEFAULT_SIGNED_CHAR 0

#define TARGET_ENDIAN_DEFAULT 0

/* A C statement to output something to the assembler file to switch to section
   NAME for object DECL which is either a FUNCTION_DECL, a VAR_DECL or
   NULL_TREE.  Some target formats do not support arbitrary sections.  Do not
   define this macro in such cases.  */

#define ASM_OUTPUT_SECTION_NAME(FILE, NAME) \
	fprintf (FILE, "\t.section %s,\"aw\",@progbits\n", (NAME))
	
/* Xeeynamo: force to use little-endian */
#define MIPSEL
#define BYTES_BIG_ENDIAN 0
#define WORDS_BIG_ENDIAN 0

#include "mips/mips.h"

