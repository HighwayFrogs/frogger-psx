-- This script was used to debug the 'aspsx' assembler, to determine the exact string getting hashed.
-- Table seems to always be 4272982 or 0x413356.
-- It also seems the provided string cuts off the first character.

function debugger_onBreakpoint()
    if (EIP ~= 0x0040202f) then return 0 end -- ignore user-set breakpoints

	AL = EAX & 0xFF
	print("Hash(\"" .. readString(ESI) .. "\", AL: " .. AL .. ", EBX: " .. EBX .. ")")
	
    debug_continueFromBreakpoint(co_run) -- continue execution
    return 0 -- let CE know we handled breakpoint, no need to update debugger form
end

createProcess("C:\\PSX\\psyq40\\bin\\aspsx.exe", "C:/Users/david/AppData/Local/Temp/PQ3 -o C:/Users/david/Desktop/Games/Git/Frogger/source/sprdata.obj", true, true)
-- openProcess("aspsx.exe")
debugProcess()
debug_setBreakpoint(0x0040202f)