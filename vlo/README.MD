# Recreating the missing files in the VLO folder
.VLO is a file type created by Millennium Interactive to hold textures / images in their games.  
The tool which made VLO files (Vorg) also generated files which belong in this folder called `frogvram.c` and `frogvram.h`.  
Unfortunately, the source code backup this repository is built from did not include `frogvram.c` and `frogvram.h`.  
So, in order to make this code usable, we needed to recreate those files.  
`frogvram.c` only contained variable definitions however, so for many of them it was fairly simple to recreate, just by taking data out of a build of the game.  
However, for every single texture in the game, there is a global variable defined in `frogvram.c`. This allowed the code to reference a particular texture.  
For textures that are referenced by the code, the other places in the code would tell us the variable names, because they were used.  
But for the hundreds / thousands which aren't explicitly referenced in the code, we have to make our own.  
For the ones which aren't referenced by the other game code, we can just give it whatever variable name we want right?  
Yes, but it's more complicated than that. If you want to perfectly match an executable (something we want to make this repository match the final version of the game), I discovered that the variable name is important to determining how the variables are ordered in memory.  

## What is texmacro.h?
Notably, there's a file in here which we generated ourselves: `texmacro.h`.  
Looking inside, its contents look pretty much like gibberish. It renames the names of variables such as `im_img463` to `im_img463_Fzwyid`.   
Believe it or not, thjis black magic fixes our problem/orders our variables correctly.  
To understand why, we must consider how memory is laid out in the executable.  
For most things in the executable, like functions, the order they are written into the source code files is the same order they will be put in the compiled code / executable.  
So for example, if you write code for `FunctionA()` before `FunctionB()`, `FunctionA()` will be placed before `FunctionB()` in the compiled code / executable.  
HOWEVER, because the tools used to write code for the PlayStation were made from scratch specifically for game consoles, it's a lot more susceptible to unusual quirks.  
Unlike functions, uninitialized memory (variables which are 0/empty when the game sets up) get ordered in a way which is a bit complicated to explain.  
All of that uninitialized data gets put into a part of the executable called the **.bss section**.  

**Why does this matter?**  
This hits Frogger very hard because Frogger has nearly 2000 uninitialized texture variables in `frogvram.c`, which means about 2000 variables are ordered improperly, which makes it very hard to decomp / compare against real versions of the game.  
Thus, in order to create a matching build of the game, we need to understand how to create names for those variables in juuust the right way to be ordered the way the original game ordered them.  
This same problem can theoretically impact any PSX decompilation project which uses the original assembler / linker, so figuring out how to create those names is important.   

## How do you compile the game?
I had to reverse engineer both the assembler and linker to understand how this process works.  
NOTE: The reverse engineering on this stuff was done maybe a year or two ago, and it's possible I may have misremembered or misdocumented some of the details. Overall this should give a good idea of how the process works though.  
Because this is a highly technical problem, I'm going to try and cover most of the bases, starting at the basics.  

Let's start at a simplified view of the compilation process.
This process starts at "I have a folder of .C source code files", and ends at "I have compiled the game into an executable that can run on a PlayStation.":  
 - **Step #1)** The preprocessor (`CPPPSX.EXE`) takes an individual .C file, and preprocesses it (Evaluates macros, includes structs from #include'd header files, etc), and creates a modified C source file which includes all the information necessary to be compiled on its own.  
 - **Step #2)** The compiler (`CC1PSX.EXE`) takes the preprocessed C file and turns it into an assembly text file. This assembly includes assembly instructions for the code, but also includes information like variable definitions or references to variables in other files.  
 - **Step #3)** The assembler (`ASPSX.EXE`) takes the assembly text and creates a .OBJ file (compiled code).  
 - **Step #4)** The previous 3 steps are repeated for every single source (.C) file included in the project.  
 - **Step #5)** The linker (`PSYLINK.EXE`) takes all of the .OBJ files and combines (links) them together to create a single .CPE file, which contains all of the game code. This file is the executable, the file a Sony PlayStation runs when playing a game.  


To better follow this process, we should break it down by each step, starting with the compiler.  
### Step #2) The Compiler
The compiler takes preprocessed C and outputs assembly code as a human-readable text file. Scrolling all the way to the bottom, you'll get your uninitialized text files.
Here's a snippet from `FROG.C`'s compiler output:
```
...
	.comm	Frogs,2736
	.comm	Frog_player_data,32
...
```
The two uninitialized variables in this file are written in the order they are seen in `FROG.C`.  
The compiler is not the cause of the variable reordering. The compiler puts the variables right next to each other, but in the actual executable there are nearly 700 different variables in-between them.  

### Step #3) The Assembler
The assembler creates a .obj file from the assembly, which came from the .C source code. So, a .obj is compiled code from a single .C file.  
They also have the previously mentioned **.bss section**, which as we recall is where our texture variables that are placed out of order reside.  
I will be referring to "uninitialized global variables" as just "symbols" now.  
After doing some reverse engineering, here's how the assembler orders symbols in that **.bss section**.  

**How does it track symbols?**  
The assembler wants to be able to work with symbols quickly. If you want to use a symbol, it's nice to be able to quickly check things such as "Have I already seen a symbol called 'Frogs'?" or "How large is the symbol named 'Frog_player_data'?"
A simple way to keep track of symbols in memory would be a list. (For anyone interested, it's a linked list)  
If you want to find a symbol by its name, you'd start at the first symbol and ask "Is the name of this symbol the same as the name of the symbol I'm looking for?"
If that is the name you're looking for, then the symbol has been found. Otherwise, try again but with the next symbol in the list.
Keep doing that and you'll either find the symbol you wanted, or reach the end, meaning there was no symbol which had the name you were looking for.  
The problem with this method is that it could be slow. Frogger has approximately 2000 uninitialized variables, so every time the assembler needs to lookup a symbol by its name, it might need to check all 2000.  
This is pretty fast on modern computers, but imagine computers of the 90s, or a game which had tens of thousands of them instead of just 2000.  

**How'd they speed it up?**  
The solution they chose to speed it up is called a "hash bucket".  
Or, put simply, instead of having 1 list with 2000 symbols, they have 256 separate lists which had an average of 3-4 symbols each.  
That means that if you know how to choose which list would contain your symbol, you only check 3-4 symbols instead of 2000.  
This general idea is called "hashing". It means they turn something large (like a symbol name) into a number called a "hash".  
The important thing about a hash is that if you provide the same input, the hash should always be the same.  
So, when you hash "Frog_player_data", you know the number you get back corresponds to the right list.  
In this case, the hash is a number between 0 and 255 which corresponds to one of the 256 different lists, so when you hash a symbol name like "Frog_player_data", the hash identifies which list to check.  

**Great, so how does this actually impact the order of the Frogger texture variables?**  
When the assembler creates the **.bss section**, it builds it by going through all of these lists, starting at the first list (the list for hash 0) and ending at (the list for hash 255).  
So, in order to control the order of the **.bss section** at the assembler step, you need to control the hash of a variable name (by choosing a variable name that does what you want).  
A lower hash number such as 32 would be placed in the **.bss section** before the hash number 164 because the list for hash number 32 is used before the list for hash number 164.  
But what happens to the order when two symbols have the same hash? It depends on the order of the list. So, the value earlier in the list will be placed before the value later in the list.  
Values are added by ASPSX.EXE in the order which they are defined. In other words, The order which they were read from compiler output. Which was the order they were defined (not declared) in the source file.  

**What's the hashing algorithm?**  
The hashing algorithm used in the assembler is very basic. It's just a sum of all the characters in a string.
The following is Java code to calculate the hash of a string. Java is provided since complex Ghidra scripts such as the one written to generate Frogger's texmacro.h are written in Java.  
```java
private static int getAssemblerHash(String input) {
	int hash = 0;
	for (int i = 0; i < input.length(); i++)
		hash += input.charAt(i);
		
	return hash % 256;
}
```

**But it's not quite so simple.**  
We're not done yet. This only describes how the ordering works in a .obj file, it doesn't describe what the linker does when combining all of the different .obj files in a game into a single executable.  

### Step #5) The Linker
The linker takes all of the separate .obj files and combines them all into a single executable.  
Understanding the previous section about the assembler is required to understand this section, because it builds upon many of the same concepts.  
Just like the assembler, the linker also uses a hash bucket system for tracking symbols.  
This time, because a linker's purpose is to combine all of the .objs, it is tracking ALL of the different symbols in the game, instead of just from a single file.  
Because the linker tracks many more symbols than the assembler, they increased the amount lists tracked from 256 to 512.  
The linker hash algorithm has also changed slightly too, and the order of the bss section in the .obj is now no more than a tiebreaker.  

**The new hashing algorithm:**  
The hash algorithm is very similar to before, except this time the length of the symbol name is also added to the hash. This allows for a really helpful trick which I'll explain later.  
Also, the hash is now from 0 to 511 because the amount of lists was increased.  
Once again, the following is Java code to calculate the linker hash of a string. Java is provided since complex Ghidra scripts such as the one written to generate Frogger's texmacro.h are written in Java.  
```java
private static int getAssemblerHash(String input) {
	int hash = input.length();
	for (int i = 0; i < input.length(); i++)
		hash += input.charAt(i);
		
	return hash % 512;
}
```

**How does the order get determined in the linker?**  
The linker operates very similarly as the assembler. The linker will make the **.bss section** by going through each of the 512 symbol lists, so the smaller the linker hash, the earlier the symbol will be placed in the executable.  
For symbols which share the same hash (are part of the same list), the order they are placed in the executable is the same as the order of the list they are on.

**So what determines the order of each list of symbols?**  
The linker will first process all .lib files in the linker script, in order (I think). This means any symbols from .lib files will be placed into the lists earlier (and thus placed into the executable earlier than others with the same linker hash).  
Then, the linker will process all of the .obj files in the linker script, in order. However, symbols from each .obj file are processed in reverse. So, the last symbol in a .obj is the first one added to the linker list.  
Thus, the tiebreaker behavior of how the list is sorted first depends on if the symbols came from the same obj file. If they didn't, sort based on which obj was read first.
If they were from the same .obj file, 
The linker goes through all of the .obj files in the order shown in the linker script.
It processes symbols in REVERSE the order of how they are in the .obj file, which will impact the order when tiebreakers occur.  

## The Solution
This all started with texmacro.h, hopefully now its purpose makes sense.  
texmacro.h is a file which turns nice readable variable names like `im_img1399` into `im_img1399_WR5D55015110100B110200211016` when compiled, in order to force the assembler & linker to order texture variables correctly in the executable, so the build is a byte-match.  
I made [this ghidra script](/sdk/ghidra-scripts/VramHeaderExporter.java) which is what generates texmacro.h.  
It makes many assumptions which are true for Frogger but may not be valid for other games, however if you need to solve this problem I would strongly recommend reading it.  
Ghidra scripts were a very obvious choice to generate these variable names in the case of Frogger, but in theory anything with the right information can generate these.  

**A special technique regarding string length:**  
The assembler hash is not impacted by the length of the symbol name, but the linker hash is.  
This is a very useful quirk because of what it means for certain strings such as `_Yah0I`.  
`_Yah0I` has a linker hash of 0, but an assembler hash of 250.  
Therefore, if you add `_Yah0I` to the end of a variable name, it will change the assembler hash without changing the linker hash. It can be added as many times as necessary too.  
This is very helpful because it provides a very easy way to reorder variables that should share the same linker hash, but their assembler hash causes them to be ordered incorrectly.  

### Order Checklist
The following is a checklist which can be followed to determine if two symbols are ordered in the way they would be if compiled by the linker.  
This checklist should make it a lot easier to debug / diagnose when something isn't ordered the way you expect.   

1) Compare the previous symbol's linker hash with the current symbol's linker hash:  
 - If previousLinkerHash > currentLinkerHash, the order is incorrect  
 - If previousLinkerHash < currentLinkerHash, the order is correct  
 - If previousLinkerHash == currentLinkerHash, continue to step 2  

2) Compare the previous symbol's assembler hash with the current symbol's assembler hash:  
 - If previousAssemblerHash > currentAssemblerHash, the order is correct  
 - If previousAssemblerHash < currentAssemblerHash, the order is incorrect  
 - If previousAssemblerHash == currentAssemblerHash, continue to step 3  
 
3) Compare the obj files each symbol comes from:  
 - If previousSymbolObjFile is linked before currentSymbolObjFile, the order is correct  
 - If previousSymbolObjFile is linked after currentSymbolObjFile, the order is incorrect  
 - If both symbols come from the same file, go to step 4  

4) Which symbol was declared earlier in the source file?  
 - If previousSymbol was defined first, the order is incorrect (due to the linker reversing symbol order when reading a .obj file)
 - If currentSymbol was defined first, the order is correct (due to the linker reversing symbol order when reading a .obj file)
 - If they are the same symbol, why did you go through this checklist?