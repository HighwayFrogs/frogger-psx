// Tests data between programs.
//@author Kneesnap
//@category Data
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;

import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.flatapi.FlatProgramAPI;

import java.lang.Throwable;
import java.util.*;
import java.lang.RuntimeException;
import java.lang.StringBuilder;
import java.io.*;

public class DataTester extends GhidraScript {
	
    @Override
    protected void run() throws Exception {
		if (currentProgram == null) {
			printerr("No current program");
			return;
		}
		
		Program targetProgram = getTargetProgram();
		if (targetProgram == null)
			return;
		
		FlatProgramAPI targetAPI = new FlatProgramAPI(targetProgram, this.monitor);
		
		String symbolName;
		try {
			symbolName = askString("Input", "What is the name of the symbol you'd like to start from?");
		} catch (Exception ex) {
			return;
		}
		
		List<Symbol> symbols = getSymbols(symbolName, null);
		if (symbols.size() != 1) {
			popup("Expected 1 symbol named '" + symbolName + "' in the main program. (Got: " + symbols.size() + ")");
			return;
		}
		
		Symbol startSymbol = symbols.get(0);
		
		symbols = targetAPI.getSymbols(symbolName, null);
		if (symbols.size() != 1) {
			popup("Expected 1 symbol named '" + symbolName + "' in the target program. (Got: " + symbols.size() + ")");
			return;
		}
		Address targetAddress = symbols.get(0).getAddress();
		
		try {
			targetAPI.start();
			compareData(startSymbol, targetAPI, targetAddress);
			targetAPI.end(true);
		} catch (Exception ex) {
			targetAPI.end(false);
			throw new RuntimeException("Exception occurred while comparing data.", ex);
		}
		
		println("Success.");
	}
	
	private void compareData(Symbol startSymbol, FlatProgramAPI targetAPI, Address targetAddress) throws Exception {		
		// How this works.
		// 1) Always select the program with labels as your main program.
		// 2) Select your target program (50b)
		// 3) Choose a starting symbol.
		// 4) Using a 4-byte look ahead buffer, read bytes from both.
		// 5) When a discrepancy is found (and data from both are not pointers), then print the address and label. Then, stop.
		// 6) Apply labels to the target program for as long as bytes match.
		
		Symbol currSymbol = startSymbol;
		while (currSymbol != null) {
			Symbol nextSymbol = getSymbolAfter(currSymbol);
			while (nextSymbol != null && isDefaultLabel(nextSymbol))
				nextSymbol = getSymbolAfter(nextSymbol);
			
			if (nextSymbol == null)
				break;
			
			long size = nextSymbol.getAddress().getOffset() - currSymbol.getAddress().getOffset();
			println(currSymbol.getName() + " -> " + nextSymbol.getName() + ", " + currSymbol.getAddress() + " + " + size);
			
			byte[] sourceData = getBytes(currSymbol.getAddress(), (int)size);
			byte[] targetData = targetAPI.getBytes(targetAddress, (int)size);
			if (sourceData.length != size || targetData.length != size)
				throw new RuntimeException("Somehow, we read the wrong number of bytes! (Size: " + size + ", Source: " + sourceData.length + ", Target: " + targetData.length + ")");
			
			Symbol targetLabelAt = targetAPI.getSymbolAt(targetAddress);
			
			// If the label exists, verify it matches.
			if (!isDefaultLabel(targetLabelAt) && !targetLabelAt.getName().equals(currSymbol.getName())) {
				println("Name mismatch at " + currSymbol.getName() + "/" + targetLabelAt.getName() + "!");
				println("Source: " + currSymbol.getAddress() + ", Target: " + targetAddress);
				return;
			}
			
			long labelEnd = targetAddress.add(size).getOffset();
			Symbol targetLabelAfter = targetAPI.getSymbolAfter(targetAddress);
			while (targetLabelAfter != null && labelEnd > targetLabelAfter.getAddress().getOffset() && isDefaultLabel(targetLabelAfter))
				targetLabelAfter = targetAPI.getSymbolAfter(targetLabelAfter);
			
			// Found a conflicting label.
			if (targetLabelAfter != null && labelEnd > targetLabelAfter.getAddress().getOffset()) {
				println("Label mismatch at " + currSymbol.getName() + "/" + targetLabelAfter.getName() + "!");
				println("Source: " + currSymbol.getAddress() + ", Target: " + targetAddress + "/" + targetLabelAfter.getAddress());
				return;
			}
			
			// Verify bytes are good.
			for (int i = 0; i < (int) size; i++) {
				if (isPointer(sourceData, i) && isPointer(targetData, i)) {
					i += 3; // Skip to after the pointer.
					continue;
				}
				
				if (sourceData[i] == targetData[i])
					continue; // Data matches.
				
				println("Data mismatch at " + currSymbol.getName() + "!");
				println("Source: " + currSymbol.getAddress().add(i) + ", Target: " + targetAddress.add(i));
				return;
			}
			

			// Apply label.
			if (isDefaultLabel(targetLabelAt))
				targetAPI.createLabel(targetAddress, currSymbol.getName(), true, SourceType.IMPORTED);
			
			// Next symbol.
			currSymbol = nextSymbol;
			targetAddress = targetAddress.add(size);
		}
	}
	
	private boolean isDefaultLabel(Symbol symbol) {
		if (symbol == null || !symbol.isPrimary())
			return true;
		
		return symbol.getSource() != SourceType.USER_DEFINED && symbol.getSource() != SourceType.IMPORTED;
		
		/*return symbol == null || !symbol.isPrimary() || symbol.getName().startsWith("DAT_800")
			|| (symbol.getName().startsWith("PTR_") && symbol.getName().contains("_800"))
			|| symbol.getName().startsWith("switchD_800");*/
			
	}
	
	private boolean isPointer(byte[] data, int index) {
		return data.length > index + 3
			&& data[index + 3] == (byte)-128 // 0x80
			&& (data[index + 2] & 0b11110000) == 0;
	}
	
	private Program getTargetProgram() throws Exception {
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
		
		return targetProgram;
	}
}