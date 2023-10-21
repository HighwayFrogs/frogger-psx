// Finds functions which have the wrong $gp value applied.
//@author Kneesnap
//@category Functions
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Function;
import ghidra.program.model.lang.Register;
import ghidra.program.model.lang.RegisterValue;
import ghidra.program.model.symbol.SourceType;
import ghidra.app.cmd.disassemble.DisassembleCommand;

import java.lang.Throwable;
import javax.swing.*;
import java.util.*;
import java.lang.RuntimeException;
import java.lang.StringBuilder;
import java.io.*;
import java.nio.file.Files;
import java.math.BigInteger;

public class FunctionGPApplier extends GhidraScript {
	private static final long GP_REGISTER = 0x800b9780L;
	// Frogger 50b = 0x800b9780 (Yes, it's detected as 800c9780, but this is wrong.)
	// Frogger US PSX Demo = 0x800AA8A8
	
	@Override
	protected void run() throws Exception {
		Register register = currentProgram.getRegister("gp");
		RegisterValue regValue = new RegisterValue(register, BigInteger.valueOf(GP_REGISTER));
		
		Function endAt = getLastFunction();
		
		Function currentFunc = getFirstFunction();
		while (currentFunc != null && currentFunc != endAt) {
			Function nextFunc = getFunctionAfter(currentFunc);
			
			AddressSetView body = currentFunc.getBody();
			Address minAddress = body.getMinAddress();
			Address maxAddress = body.getMaxAddress();
			RegisterValue currentValue = currentProgram.getProgramContext().getRegisterValue(register, minAddress);
			
			boolean hasValue = currentValue != null && currentValue.hasValue();
			if (hasValue && !currentValue.getUnsignedValue().equals(BigInteger.valueOf(GP_REGISTER))) {
				println("Fixing " + currentFunc.getName() + " (Old: " + (hasValue ? currentValue.getUnsignedValue() : "None") + ")");
				currentProgram.getProgramContext().setRegisterValue(minAddress, maxAddress, regValue);
				clearListing(body, true, false, false, false, false, false, false, false, true, true, true, false);
				runCommand(new DisassembleCommand(minAddress, null, true));
			}
						
			currentFunc = nextFunc;
			
		}
	}
}