// Exports the frogvram files. May only work well in Frogger because all the images are not null.
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

public class SoundTableExporter extends GhidraScript {
	private static final boolean INCLUDE_SAMPLE_NAMES = true; // Whether or not sound sample enum names should be included.
	private static final boolean INCLUDE_INDICES = true; // Whether ids should be included in the output.
	private static final boolean INCLUDE_PROGRAM_NAMES = false; // Whether or not debug program names should be included. This should be disabled for normal exports, but is helpful when debugging or creating a config for a new version.


    @Override
    protected void run() throws Exception {
		Symbol sampleInfo = getSymbol("gSampleInfo");
		
		List<String> sampleNames = promptSampleNames();
		Map<VabID, List<String>> programNames = promptProgramNames();
		
		// Configuration info.
		boolean includeSampleNames = INCLUDE_SAMPLE_NAMES && sampleNames.size() > 0;
		boolean includeProgramNames = INCLUDE_PROGRAM_NAMES && programNames.size() > 0;
		
		// Stuff.
		StringBuilder builder = new StringBuilder();
		Address readAddress = sampleInfo.getAddress();
		String lastID = null;
		int index = 0;
		while (true) {
			Address imageDataAddress = toAddr((long)getInt(readAddress) & 0xFFFFFFFFL);
			
			int flags = getInt(readAddress);
			short vabInfoId = getShort(readAddress.add(4));
			short vabGroupId = getShort(readAddress.add(6));
			short program = getShort(readAddress.add(8));
			short tone = getShort(readAddress.add(10));
			short pitch = getShort(readAddress.add(12));
			short pitchMod = getShort(readAddress.add(14));
			short minVolume = getShort(readAddress.add(16));
			short maxVolume = getShort(readAddress.add(18));
			long sampleNamePtr = (long)getInt(readAddress.add(20)) & 0xFFFFFFFFL;
			
			// 	{MRSNDVF_SINGLE,VAB_ORIGINAL,SFX_GROUP_FROGGER,   5,	0,	 60,   60,	 0,	110,	 NULL},		// ORG_FROG_CROC_MUNCH
			
			// Empty / end line.
			if (flags == 0 && vabInfoId == 0 && tone == 0 && program == 0) {
				builder.append("\n\n\t{NULL,			0,0,					0,	0, 		0, 		0,		0,  0,		NULL},\n");
				break;
			}
			
			
			// Do normal line.
			VabID vabBank = VabID.values()[vabInfoId];
			String infoName = VabID.getName(vabInfoId);
			
			if (!infoName.equals(lastID))
				builder.append("\n");
			
			builder.append("\t{")
				.append(VabFlag.getString(flags))
				.append(",")
				.append(infoName)
				.append(",")
				.append(SoundGroup.getName(vabGroupId))
				.append(",    ")
				.append(program)
				.append(",\t")
				.append(tone)
				.append(",\t ")
				.append(pitch)
				.append(",   ")
				.append(pitchMod)
				.append(",\t ")
				.append(minVolume)
				.append(", ")
				.append(maxVolume)
				.append(",\t")
				.append(sampleNamePtr > 0 ? "ERROR_" + sampleNamePtr : "NULL")
				.append("},");
				
			if (includeSampleNames || includeProgramNames || INCLUDE_INDICES)
				builder.append("\t\t//");
			
			if (includeSampleNames) {
				String sampleName = "NO NAME";
				if (index >= 0 && index < sampleNames.size()) {
					sampleName = sampleNames.get(index);
					if (sampleName.startsWith("SFX_"))
						sampleName = sampleName.substring("SFX_".length());
				}
				
				builder.append(" ").append(sampleName);
			}
			
			if (includeProgramNames) {
				List<String> vabBankNames = programNames.get(vabBank);
				if (vabBankNames != null && vabBankNames.size() > 0) {
					builder.append(" ")
						.append(program >= vabBankNames.size() ? "NO NAME" : vabBankNames.get(program));
				}
			}
			
			if (INCLUDE_INDICES) {
				builder.append(" (")
					.append(index)
					.append(")");
			}
			
			// End line.
			builder.append("\n");
			
			readAddress = readAddress.add(24);
			lastID = infoName;
			
			index++;
		}
		
		println(builder.append("\n").toString());
    }
	
	private List<String> promptSampleNames() throws Exception {
		List<String> sampleNames = new ArrayList<>();
		if (!INCLUDE_SAMPLE_NAMES)
			return sampleNames;
		
		File file;
		try {
			// While this will load sound.H, it's recommended to store a file separately which has this, for different versions.
			file = askFile("Select the file (usually sound.H) which contains the enum definition for programs.", "Ok");
		} catch (Exception ex) {
			return sampleNames; // Cancelled.
		}
		
		for (String line : Files.readAllLines(file.toPath())) {
			if ((!line.contains("SFX_") && !line.contains("SKY_WIND")) || line.contains("SFX_GROUP_"))
				continue;
			
			String sfxName = line.split("//")[0].split(",")[0].trim();
			
			if (!sfxName.startsWith("SFX_") && !sfxName.equals("SKY_WIND")) {
				println("Don't recognize '" + sfxName + "' from '" + line + "'.");
				continue;
			}
			
			sampleNames.add(sfxName);
		}
		
		return sampleNames;
	}
	
	private Map<VabID, List<String>> promptProgramNames() throws Exception {
		Map<VabID, List<String>> programNames = new HashMap<>();
		if (!INCLUDE_PROGRAM_NAMES)
			return programNames;
		
		File file;
		try {
			file = askFile("Select the FrogLord sound bank.", "Ok");
		} catch (Exception ex) {
			return programNames; // Cancelled.
		}
		
		VabID currentId = null;
		for (String line : Files.readAllLines(file.toPath())) {
			if (line.isEmpty())
				continue;
			
			String trimmedLine = line.split("//")[0].split("#")[0].trim();
			if (trimmedLine.isEmpty())
				continue;
			
			if (trimmedLine.startsWith("[") && trimmedLine.endsWith("]")) {
				String sectionName = trimmedLine.substring(1, trimmedLine.length() - 1);
				currentId = VabID.getByName(sectionName);
				continue;
			}
			
			programNames.computeIfAbsent(currentId, key -> new ArrayList<>()).add(trimmedLine);
		}
		
		return programNames;
	}
	
	private Symbol getSymbol(String name) throws Exception {
		List<Symbol> symbols = getSymbols(name, null);
		if (symbols.size() != 1)
			throw new RuntimeException("Found " + symbols.size() + " symbols named '" + name + "'. (Expected: 1)");
		return symbols.get(0);
	}
	
	public enum SoundGroup {
		SFX_GROUP_FROGGER,
		SFX_GROUP_ENTITY,
		SFX_GROUP_UNKNOWN,
		SFX_GROUP_SELECT;
		
		public static String getName(short id) {
			if (id >= 0 && id < values().length)
				return values()[id].name();
			return "SFX_GROUP_UNKNOWN_" + id;
		}
	}
	
	public enum VabID {
		VAB_GENERIC,
		VAB_CAVES,
		VAB_DESERT,
		VAB_FOREST,
		VAB_JUNGLE,
		VAB_ORIGINAL,	
		VAB_DELETED,			// Has been removed, but is still needed for order.
		VAB_SWAMP,
		VAB_SKY,
		VAB_SUBURBIA,
		VAB_INDUSTRIAL,
		VAB_SELECT;
		
		public static String getName(short id) {
			if (id >= 0 && id < values().length)
				return values()[id].name();
			return "VAB_UNKNOWN_" + id;
		}
		
		public static VabID getByName(String name) {
			if (!name.startsWith("VAB_"))
				name = "VAB_" + name;
			
			for (VabID id : values())
				if (id.name().startsWith(name))
					return id;
			throw new RuntimeException("Couldn't get VabID for name '" + name + "'.");
		}
	}
	
	public enum VabFlag {
		MRSNDVF_INITIALISING,
		MRSNDVF_SINGLE,
		MRSNDVF_REPEAT,
		MRSNDVF_LOOPED;

		public int getMask() {
			return 1 << ordinal();
		}
		
		public static String getString(int flags) {
			if (flags == 0)
				return "NULL";
			
			StringBuilder builder = new StringBuilder();
			for (int i = values().length - 1; i >= 0; i--) {
				VabFlag flag = values()[i];
				int mask = flag.getMask();
				if ((flags & mask) != mask)
					continue;
				
				flags &= ~mask; // Remove mask bit from flags.
				if (builder.length() > 0)
					builder.append(" | ");
				builder.append(flag.name());
			}
			
			if (flags != 0) {
				if (builder.length() > 0)
					builder.append(" | ");
				builder.append("0x").append(Integer.toHexString(flags).toUpperCase());
			}
			
			return builder.toString();
		}
	}
}