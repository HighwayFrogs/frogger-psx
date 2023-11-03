// Imports an image name while hovering over the image pointer array in tempopt.c
//@author Kneesnap
//@category Data
//@keybinding ctrl shift A
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.flatapi.FlatProgramAPI;

import java.lang.Throwable;
import java.util.*;
import java.lang.RuntimeException;
import java.lang.StringBuilder;
import java.io.*;

public class ImageNameLanguageMaker extends GhidraScript {
	private static final int SYMBOL_NAME_COUNT = 5;
	
    @Override
    protected void run() throws Exception {
		List<Address> targetAddresses = findTargetImageAddresses();
		if (targetAddresses == null)
			return;
		
		// Ask for the image name template.
		String imageNameTemplate = askUserForImageNameTemplate();
		if (imageNameTemplate == null)
			return;
		
		// Generate symbol names to apply to the image pointers.
		List<String> symbolNames = generateSymbolNames(imageNameTemplate);
		if (symbolNames == null)
			return;
		
		// Apply those image names.
		start();
		try {
			applyLabels(targetAddresses, symbolNames);
			end(true);
		} catch (Exception ex) {
			end(false);
			throw new RuntimeException("Exception occurred while applying image names.", ex);
		}
		
		// Done.
		println("Applied " + symbolNames.size() + " symbol names.");
	}
	
	private List<Address> findTargetImageAddresses() {
		if (currentLocation == null) {
			printerr("No current location of cursor");
			return null;
		}
		
		Address startAddress = currentLocation.getByteAddress();
		if (startAddress == null) {
			printerr("The cursor position has no byte address.");
			return null;
		}
		
		// Verify address has pointers which are viable targets to apply.
		List<Address> addresses = new ArrayList<>();
		Address tempAddress = startAddress;
		for (int i = 0; i < SYMBOL_NAME_COUNT; i++) {
			int value;

			try {
				value = getInt(tempAddress);
			} catch (MemoryAccessException mae) {
				printerr(String.format("Failed to read memory from 0x%08X", tempAddress));
				return null;
			}
			
			if (!isPointer(value)) {
				popup(String.format("The value at 0x%08X (0x%08X) does not look like a valid pointer.", tempAddress.getOffset(), value));
				return null;
			}
			
			Address imageAddress = toAddr(value & 0xFFFFFFFFL);
			Symbol imageSymbol = getSymbolAt(imageAddress);
			if (!isDefaultLabel(imageSymbol)) {
				popup(String.format("There is already a symbol named '%s' for address 0x%08X.", imageSymbol.getName(), value));
				return null;
			}
			
			addresses.add(imageAddress);
			tempAddress = tempAddress.add(4); 
		}
		
		return addresses;
	}
	
	private String askUserForImageNameTemplate() {
		String imageNameTemplate;
		try {
			imageNameTemplate = askString("Input", "Please enter the image name to apply. Use an '*' for language replacement.");
		} catch (Exception ex) {
			// User cancelled.
			return null;
		}
		
		if (imageNameTemplate == null)
			return null;
		
		// Verify this looks like an image name.
		if (!imageNameTemplate.startsWith("im_")) {
			popup("Image names usually start with \"im_\", but \"" + imageNameTemplate + "\" did not.");
			return askUserForImageNameTemplate();
		}
		
		// Verify the template contains an asterisk.
		if (!imageNameTemplate.contains("*")) {
			popup("The provided image name \"" + imageNameTemplate + "\" did not contain a '*' character.");
			return askUserForImageNameTemplate();
		}
		
		return imageNameTemplate;
	}
	
	private List<String> generateSymbolNames(String imageNameTemplate) {
		List<String> symbolNames = new ArrayList<>();
		
		// One image symbol for each language, in the order the game orders them.
		symbolNames.add(imageNameTemplate.replace("_*", "").replace("*", ""));
		symbolNames.add(imageNameTemplate.replace("*", "i"));
		symbolNames.add(imageNameTemplate.replace("*", "g"));
		symbolNames.add(imageNameTemplate.replace("*", "f"));
		symbolNames.add(imageNameTemplate.replace("*", "s"));
		
		// Verify we have the expected amount.
		if (symbolNames.size() != SYMBOL_NAME_COUNT) {
			printerr("There were " + symbolNames.size() + " symbol names generated, but " + SYMBOL_NAME_COUNT + " were expected.");
			return null;
		}
		
		// Check if of those symbol names are already used.
		for (String symbolName : symbolNames) {
			List<Symbol> symbols = getSymbols(symbolName, null);
			if (symbols != null && symbols.size() > 0) {
				popup("There is already a a symbol named '" + symbolName + "'.");
				return null;
			}
		}
		
		return symbolNames;
	}
	
	private void applyLabels(List<Address> targetAddresses, List<String> symbolNames) throws Exception {
		if (targetAddresses.size() != symbolNames.size()) {
			printerr("There were " + targetAddresses.size() + " symbols to create, but " + symbolNames.size() + " symbol names to apply.");
			return;
		}
		
		for (int i = 0; i < symbolNames.size(); i++)
			createLabel(targetAddresses.get(i), symbolNames.get(i), true, SourceType.USER_DEFINED);
	}
	
	
	private boolean isDefaultLabel(Symbol symbol) {
		if (symbol == null || !symbol.isPrimary())
			return true;
		
		return symbol.getSource() != SourceType.USER_DEFINED && symbol.getSource() != SourceType.IMPORTED;
	}
	
	private boolean isPointer(int pointer) {
		long extendedPtr = (pointer & 0xFFFFFFFFL);
		// Tests if the value is within address space of KSEG0, since that's Main RAM.
        // The first 64K (0x10000 bytes) are skipped because it's reserved for the BIOS.
        // There is 2 MB of RAM in this area, so the data must be within such a range.
        return (extendedPtr >= 0x80010000L && extendedPtr < 0x80200000L) || (pointer >= 0x10000L && pointer < 0x200000L);
	}
}