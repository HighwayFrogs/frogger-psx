// Imports level name info for Frogger.
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

public class LevelNameImporter extends GhidraScript {
	private static final int LEVEL_COUNT = 40;
	private static final int IMAGE_COUNT = 1813;
	
    @Override
    protected void run() throws Exception {
		Address selectedAddress = currentAddress;
		
		Symbol symbol = getSymbolAt(selectedAddress);
		if (symbol == null || !symbol.getName().contains("Sel_arcade_levels"))
			throw new RuntimeException("Symbol at address was not Sel_arcade_levels.");
		
		// Read bmp pointers.
		List<Long> bmpPointers = new ArrayList<>();
		List<Symbol> bmpSymbols = getSymbols("bmp_pointers", null);
		if (bmpSymbols.size() != 1) {
			popup("Found bmp_pointers " + bmpSymbols.size() + " times. (Expected: 1)");
			return;
		}
		
		Symbol bmpPointerSymbol = bmpSymbols.get(0);
		Address bmpReadAddress = bmpPointerSymbol.getAddress();
		for (int i = 0; i < IMAGE_COUNT; i++) {
			bmpPointers.add(((long)getInt(bmpReadAddress) & 0xFFFFFFFFL));
			bmpReadAddress = bmpReadAddress.add(4);
		}
		
		// Read data from file.
		
		File file;
		try {
			file = askFile("Please select the file to read names from. (SELECT.C)", "Go.");
		} catch (Throwable th) {
			return;
		}
		
		List<String> labels = new ArrayList<>();
		List<String> tempLabels = new ArrayList<>();
		for (String line : Files.readAllLines(file.toPath())) {
			if (!line.contains("&im_") || line.contains("= &im_")) {
				if (tempLabels.size() > 0 && line.contains("}")) {
					if (tempLabels.size() > 6)
						throw new RuntimeException("Too many labels! " + tempLabels.size() + " \"" + String.join("\", \"", tempLabels) + "\"");
					while (tempLabels.size() < 6)
						tempLabels.add(null);
					
					labels.addAll(tempLabels);
					tempLabels.clear();
				}
				
				continue;
			}
			
			String[] split = line.split("&im_");
			for (int i = 1; i < split.length; i++)
				tempLabels.add("im_" + split[i].split(" //")[0].replace(" ", ",").replace("\t", ",").split(",")[0]);
		}
		
		// Read bmp pointers.
		
		Map<Integer, String> nameToId = new HashMap<>();
		Address readAddress = symbol.getAddress();
		for (int i = 0; i < LEVEL_COUNT; i++) {
			Address imageWorldSelectable = readAddress.add(24);
			Address imageWorldVisited = readAddress.add(28);
			Address imageWorldNotTried = readAddress.add(32);
			Address imageLevelTexture = readAddress.add(36);
			Address imageLevelNameTexture = readAddress.add(40);
			Address imageLevelNameTextureIngame = readAddress.add(44);
			
			Address texImageWorldSelectable = toAddr((long)getInt(imageWorldSelectable) & 0xFFFFFFFFL);
			Address texImageWorldVisited = toAddr((long)getInt(imageWorldVisited) & 0xFFFFFFFFL);
			Address texImageWorldNotTried = toAddr((long)getInt(imageWorldNotTried) & 0xFFFFFFFFL);
			Address texImageLevelTexture = toAddr((long)getInt(imageLevelTexture) & 0xFFFFFFFFL);
			Address texImageLevelNameTexture = toAddr((long)getInt(imageLevelNameTexture) & 0xFFFFFFFFL);
			Address texImageLevelNameTextureIngame = toAddr((long)getInt(imageLevelNameTextureIngame) & 0xFFFFFFFFL);
			
			if (texImageLevelNameTextureIngame.getOffset() != 0 && texImageLevelNameTexture.getOffset() != texImageLevelNameTextureIngame.getOffset())
				throw new RuntimeException("Texture level name data does not match.");
			
			if (texImageWorldVisited.getOffset() != texImageWorldNotTried.getOffset())
				throw new RuntimeException("Texture level name data does not match. (" + texImageWorldVisited + ", " + texImageWorldNotTried + ")");
			
			// Create labels.
			int baseId = (i * 6);
			createLabelOrComplain(texImageWorldSelectable, labels.get(baseId));
			createLabelOrComplain(texImageWorldVisited, labels.get(baseId + 1));
			createLabelOrComplain(texImageWorldNotTried, labels.get(baseId + 2));
			createLabelOrComplain(texImageLevelTexture, labels.get(baseId + 3));
			createLabelOrComplain(texImageLevelNameTexture, labels.get(baseId + 4));
			
			int texIdWorldNoColor = bmpPointers.indexOf(texImageWorldSelectable.getOffset());
			int texIdWorldColor = bmpPointers.indexOf(texImageWorldVisited.getOffset());
			int texIdLevelPreview = bmpPointers.indexOf(texImageLevelTexture.getOffset());
			int texIdLevelName = bmpPointers.indexOf(texImageLevelNameTexture.getOffset());
			
			store(nameToId, texIdWorldNoColor, labels.get(baseId));
			store(nameToId, texIdWorldColor, labels.get(baseId + 1));
			store(nameToId, texIdLevelPreview, labels.get(baseId + 3));
			store(nameToId, texIdLevelName, labels.get(baseId + 4));
			
			readAddress = readAddress.add(92);
		}
		
		// Print name mappings.
		StringBuilder sb = new StringBuilder("{").append("\n");
		for (Integer key : nameToId.keySet()) {
			String name = nameToId.get(key);
			sb.append(key).append("=").append(name).append("\n");
		}

		println(sb.toString());
    }
	
	private void store(Map<Integer, String> map, int id, String name) {
		if (id == -1)
			return;
		String oldValue = map.get(id);
		if (oldValue != null && !oldValue.equals(name)) {
			println("Tex ID " + id + " had name '" + oldValue + "', but was replaced with '" + name + "'.");
			return;
		}
		if (oldValue == null)
			map.put(id, name);
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