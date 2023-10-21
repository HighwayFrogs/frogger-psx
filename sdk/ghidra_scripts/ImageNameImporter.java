// Imports image name into bmp_pointers from a name mapping config. Works better with Frogger than MediEvil, since Frogger has all of its textures non-null in bss, while MediEvil has them as null.
//@author Kneesnap
//@category Functions
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.Symbol;

import java.lang.Throwable;
import javax.swing.*;
import java.util.*;
import java.lang.RuntimeException;
import java.lang.StringBuilder;
import java.io.*;
import java.nio.file.Files;

public class ImageNameImporter extends GhidraScript {
	
    @Override
    protected void run() throws Exception {
		List<Symbol> bmpSymbols = getSymbols("bmp_pointers", null);
		if (bmpSymbols.size() != 1) {
			popup("Got " + bmpSymbols.size() + " symbols named 'bmp_pointers'. (Expected: 1)");
			return;
		}
		
				
		Symbol bmpPointerSymbol = bmpSymbols.get(0);
		Address bmpBaseAddress = bmpPointerSymbol.getAddress();
				
		File file;
		try {
			file = askFile("Please select the file to read names from.", "Go.");
		} catch (Throwable th) {
			return;
		}
		
		for (String line : Files.readAllLines(file.toPath())) {
			if (line.contains("#"))
				line = line.split("#")[0].trim();
			if (!line.contains("="))
				continue;
			
			String[] split = line.split("=");
			int id = Integer.parseInt(split[0]);
			String name = split[1];
			
			Address targetAddress = bmpBaseAddress.add(4 * id);
			Address textureAddress = toAddr(((long)getInt(targetAddress) & 0xFFFFFFFFL));
			createLabelOrComplain(textureAddress, name);
		}
    }
	
	private void createLabelOrComplain(Address at, String labelName) throws Exception {
		if (labelName == null || at.getOffset() == 0)
			return;
		
		Symbol oldLabel = getSymbolAt(at);
		if (oldLabel != null && oldLabel.isPrimary() && !oldLabel.getName().startsWith("DAT_") && !oldLabel.getName().equals(labelName)) {
			println("Old label '" + oldLabel.getName() + "'@" + at + " can't be replaced with '" + labelName + "'.");
			return;
		}
		
		createLabel(at, labelName, true);
	}
}