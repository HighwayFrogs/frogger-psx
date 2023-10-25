// Exports labels with their address, used to generate decomp project symbol list text files.
//@author Kneesnap
//@category Data
//@keybinding
//@menupath
//@toolbar

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.Symbol;

import java.lang.Throwable;
import java.util.*;
import java.lang.RuntimeException;
import java.lang.StringBuilder;
import java.io.*;
import java.nio.file.Files;

public class LabelExporter extends GhidraScript {	
    @Override
    protected void run() throws Exception {
		Symbol symbol = getSymbolAt​(toAddr(0x80010000L));
		
		StringBuilder builder = new StringBuilder();
		List<String> lines = new ArrayList<>();
		while (symbol != null) {
			if (symbol.getName().startsWith("switchdataD") || symbol.getName().startsWith("FUN_") || symbol.getName().startsWith("DAT_") || symbol.getName().startsWith("caseD_") || symbol.getName().startsWith("switchD")) {
				symbol = getSymbolAfter(symbol);
				continue;
			}
			
			String line = String.format("%s=0x%08X;", symbol.getName(), symbol.getAddress().getOffset());
			builder.append(line).append('\n');
			lines.add(line);
			symbol = getSymbolAfter(symbol);
		}
		
		Files.write(new File("symbols.txt").toPath(), lines);
		println(builder.toString());
		println(lines.size() + " symbols saved.");
    }
}