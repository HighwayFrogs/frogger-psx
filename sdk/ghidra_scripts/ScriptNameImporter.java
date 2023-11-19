// Imports script names into Scripts from a name mapping config.
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

public class ScriptNameImporter extends GhidraScript {
	
	@Override
	protected void run() throws Exception {
		// exportScripts();
		List<Symbol> scriptSymbols = getSymbols("Scripts", null);
		if (scriptSymbols.size() != 1) {
			popup("Got " + scriptSymbols.size() + " symbols named 'Scripts'. (Expected: 1)");
			return;
		}
		
				
		Symbol scriptPointerSymbol = scriptSymbols.get(0);
		Address scriptBaseAddress = scriptPointerSymbol.getAddress();
				
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
			
			Address targetAddress = scriptBaseAddress.add(4 * id);
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
	
	private void exportScripts() throws Exception {
		List<Symbol> scriptSymbols = getSymbols("Scripts", null);
		if (scriptSymbols.size() != 1) {
			popup("Got " + scriptSymbols.size() + " symbols named 'Scripts'. (Expected: 1)");
			return;
		}
		
				
		Symbol scriptPointerSymbol = scriptSymbols.get(0);
		Address scriptBaseAddress = scriptPointerSymbol.getAddress();
		
		StringBuilder builder = new StringBuilder("\n");
		for (int i = 0; i < 183; i++) {
			Address targetAddress = scriptBaseAddress.add(4 * i);
			Address scriptAddress = toAddr(((long)getInt(targetAddress) & 0xFFFFFFFFL));
			Symbol symbol = getSymbolAt(scriptAddress);
			if (symbol == null)
				continue;
			
			builder.append(i)
				.append("=")
				.append(symbol.getName())
				.append('\n');
		}
		
		println(builder.toString());
	}
}