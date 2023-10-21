// Tests function signatures between programs.
//@author Kneesnap
//@category FunctionID
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

import ghidra.feature.fid.hash.FidHashQuad;
import ghidra.feature.fid.service.FidService;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;

import java.lang.Throwable;
import java.util.*;
import java.lang.RuntimeException;
import java.lang.StringBuilder;
import java.io.*;

public class SignatureTester extends GhidraScript {
	
    @Override
    protected void run() throws Exception {
		if (currentProgram == null) {
			printerr("No current program");
			return;
		}
		
		FidService service = new FidService();
		
		// Load functions from target program.
		Map<Long, Function> targetFunctions = getTargetFunctions(service);
		if (targetFunctions == null)
			return;
		
		
		
		Function function = null;
		Function nextFunc = getFirstFunction();
		Function endFunc = getLastFunction();
		
		int matchingFunctions = 0;
		int nonMatchingFunctions = 0;
		while (nextFunc != null) {
			if (this.monitor.isCancelled())
				return;
			
			function = nextFunc;
			nextFunc = (function != endFunc) ? getFunctionAfter(function) : null;
			
			// Hash the function.
			FidHashQuad hashFunction = service.hashFunction(function);
			if (hashFunction == null)
				continue; // Function too small.
			
			long hash = hashFunction.getFullHash();
			
			Function matchingFunc = targetFunctions.get(hash);
			if (matchingFunc != null) {
				matchingFunctions++;
			} else {
				nonMatchingFunctions++;
				println("Function '" + function.getName() + "' was not found in the target.");
			}
		
			/*println("FID Hash for " + function.getName() + " at " + function.getEntryPoint() + ": " +
				hashFunction.toString());*/
		}
		
		println("Matching Functions: " + matchingFunctions);
		println("Non Matching Functions: " + nonMatchingFunctions);
	}
		
	private Map<Long, Function> getTargetFunctions(FidService service) throws Exception {
		Program targetProgram;
		try {
			targetProgram = askProgram("Please select the executable to compare.");
		} catch (Exception ex) {
			return null;
		}
		
		if (targetProgram == currentProgram) {
			popup("The program chosen to test matches the active program.");
			return null;
		}
			
		Map<Long, Function> functionsByHash = new HashMap<>();
		FunctionIterator functions = targetProgram.getFunctionManager().getFunctions(true);
		for (Function function : functions) {
			if (this.monitor.isCancelled())
				return null;
				
			FidHashQuad hashQuad = service.hashFunction(function);
			if (hashQuad == null)
				continue; // Function too small.
				
			functionsByHash.put(hashQuad.getFullHash(), function); // getFullHash() seems to give better results than getSpecificHash().
		}
			
		return functionsByHash;
    }
}