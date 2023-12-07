# This is not a Linux Port
As part of making Frogger compileable on Linux, we had a problem. The PlayStation SDK had two assemblers, one was for compiler output, the other was for hand-written assembly.  
The assembler for hand-written assembly (`ASMPSX.EXE`) uses syntax different from the one for compiler output (`ASPSX.EXE`).  
Because there is no equivalent as part of the GNU toolchain, something needed to be done. The files here are conversions of the hand-written assembly files into GNU AS assembly syntax.  
This allows building in a Linux environment.  
