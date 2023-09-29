-- This script was used to debug the 'psylink' linker, to determine the exact string getting hashed.

function debugger_onBreakpoint()
    if (EIP ~= 0x004077ac) then return 0 end -- ignore user-set breakpoints

--	print("ESI is " .. string(ESI))
	print("File is " .. readString(EDX + 22))
	if (ESI == 0x40f5fe) then
		
	    return 0 -- Tell CE to pause.
	end
	
    debug_continueFromBreakpoint(co_run) -- continue execution
    return 1 -- let CE know we handled breakpoint, no need to update debugger form
end

createProcess("C:\\Users\\david\\Desktop\\Games\\Git\\Frogger\\source\\psylink.exe", "/n512 /c /m /wl /wm /l C:\\PSX\\psyq40\\LIB @makefile.lnk,main.cpe,main.sym,main.map", true, false)
-- openProcess("psylink.exe")
debugProcess()
debug_setBreakpoint(00402aec)