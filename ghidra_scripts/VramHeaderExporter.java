// Exports the frogvram files. May only work well in Frogger because all the images are defined.
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
import ghidra.program.model.symbol.SourceType;

import java.lang.Throwable;
import javax.swing.*;
import java.util.*;
import java.lang.RuntimeException;
import java.lang.StringBuilder;
import java.io.*;
import java.nio.file.Files;
import java.util.Map.Entry;
import java.util.regex.Pattern;
import java.lang.System;
import java.util.Arrays;

// This script is used to recreate the .c and .h files created by Vorg, the in-house image management software.
// However, there is some degree of complexity here. The '.bss' section is not ordered like the rest of the symbols in the executable.
// A hashing process is used, as the symbols are seemingly stored in a hash table.
// This means we must output names which satisfy the sorting conditions in order to recreate the original order.

// How exactly does the length sort work?
// It's not actually done in the linker, and it's not even explicit as previously assumed.
// For hash values under 256, we know the result of the assembler hash is the same as the linker hash on the modulo side.
// But it's slightly different still. The assembler hash doesn't consider length, while the linker hash does.
// This means if you have two strings with different lengths but a matching linker hash, the larger string will have a smaller assembler hash.
// So, this will effectively sort the strings from largest to smallest, which when read backwards by the linker, will be reversed and cause the smaller strings to be placed first.

// How does this break im_swp5pic? Still need to work out the details.
// So, here's the problem. im_swp5pic has an assembler hash of zero. This means larger strings which evaluate to the same linker hash will be less than zero, wrapping around.
// Thus, the assembler hashes are greater for them, breaking the sorting. So we have a system to counteract this.

public class VramHeaderExporter extends GhidraScript {
	private static final boolean GENERATE_BSS_NAMES = true;
	private static final boolean DEBUG_HASHES = true; // This should be used when debugging hashes.
	private static final boolean APPLY_AUTO_LABELS = false; // Whether generated image labels should be applied. Generally false.
	private static final boolean APPLY_HASHES_WHEN_UNSURE = true; // If we cannot confirm an image's hash number perfectly, setting this option to true will give one which is likely to work, but may conflict if any non-texture data is present in the area.
	
	private static final Pattern AUTO_PATTERN = Pattern.compile("im_img(\\d+)");
	private static final Set<String> LIB_SYMBOLS = new HashSet<>(Arrays.asList(
		"_svm_okon1", "_svm_okon2", "_svm_orev1", "_svm_orev2", "Stframe_no", "SsFCALL", "_svm_voice", "_svm_rattr",
		"Stsector_offset", "StRgb24", "StMode", "_svm_sreg_dirty", "StFunc1", "StFunc2", "_svm_vab_pg", "StCdIntrFlag",
		"_svm_vab_vh", "_svm_damper", "_svm_vab_tn", "_spu_RQ", "StCHANNEL", "StStartFrame", "_svm_stereo_mono",
		"_snd_ev_flag", "kMaxPrograms", "_svm_pg", "_svm_vg", "_svm_vh", "_svm_tn", "CChannel", "_SsVmMaxVoice", "StFinalSector",
		"_snd_openflag", "_autopan", "_svm_cur", "_svm_vab_used", "GlobalCallback", "_svm_sreg_buf", "_autovol", "StEmu_Idx",
		"_svm_auto_kof_mode", "_svm_envx_ptr", "_que", "VBLANK_MINUS", "StRingIdx1", "StRingIdx2", "StRingIdx3",
		"SpuCommonError", "_ss_score", "_SsMarkCallback", "_snd_seq_s_max", "StEmu_Addr", "_snd_seq_t_max", "StEndFrame",
		"StSTART_FLAG", "StRingBase", "StRingAddr", "_svm_vab_total", "_svm_vab_count", "_svm_vab_start", "_svm_envx_hist",
		"StRingSize", "_svm_okof1", "_svm_okof2"));
	
	private static final Set<String> USED_EARLY_SYMBOLS = new HashSet<>(Arrays.asList("im_gatso"));
	
	@Override
	protected void run() throws Exception {
		// Read bmp pointers.
		List<Long> bmpPointers = new ArrayList<>();
		List<Symbol> bmpSymbols = getSymbols("bmp_pointers", null);
		if (bmpSymbols.size() != 1) {
			popup("Found " + bmpSymbols.size() + " symbols named 'bmp_pointers'. (Expected: 1)");
			return;
		}
			
		Symbol startSymbol = bmpSymbols.get(0);
		
		StringBuilder mismatchBuilder = new StringBuilder();
		
		Address readAddress = startSymbol.getAddress();
		List<ImageHeader> unorderedImages = new ArrayList<>();
		Set<String> imageSymbolNames = new HashSet<>();
		int texIndex = 0;
		while (true) {
			long imageDataAddressOffset = (long)getInt(readAddress) & 0xFFFFFFFFL;
			if ((imageDataAddressOffset & 0xFFF00000L) != 0x80000000L)
				break; // Reached end.
			
			Address imageDataAddress = toAddr(imageDataAddressOffset);
			
			Symbol symbol = getSymbolAt(imageDataAddress);
			String name = (symbol != null && !symbol.getName().startsWith("DAT_")) ? symbol.getName() : null;
			
			// If an auto-generated name has been applied, don't use it.
			if (name != null && AUTO_PATTERN.matcher(name).matches())
				name = null;
			
			// If it's auto-generated, and should be updated, update the label.
			if (name == null && APPLY_AUTO_LABELS) {
				if (symbol != null && (symbol.getSource() == SourceType.USER_DEFINED || symbol.getSource() == SourceType.IMPORTED))
					if (!removeSymbol(imageDataAddress, symbol.getName()))
						throw new RuntimeException("Couldn't remove symbol '" + symbol.getName() + "' at " + imageDataAddress + ".");
				
				createLabel(imageDataAddress, "im_img" + texIndex, true, SourceType.IMPORTED);
			}
			
			if (name != null)
				imageSymbolNames.add(name);
			
			if (name == null || !USED_EARLY_SYMBOLS.contains(name))
				unorderedImages.add(new ImageHeader(name, imageDataAddress, texIndex));
			
			readAddress = readAddress.add(4);
			texIndex++;
		}
		println("Found " + unorderedImages.size() + " images.");
		
		// Applies hashes which we can infer are correct.
		List<ImageHeader> sortedImagesByAddressOrder = new ArrayList<>(unorderedImages);
		sortedImagesByAddressOrder.sort(Comparator.comparingLong(image -> image.address.getOffset()));
		
		List<HashedSymbol> symbolsByAddressOrder = new ArrayList<>();
		
		Address symbolSearch = sortedImagesByAddressOrder.get(0).address;
		long symbolSearchEnd = sortedImagesByAddressOrder.get(sortedImagesByAddressOrder.size() - 1).address.getOffset();
		println("Finding symbols between " + symbolSearch + " and " + sortedImagesByAddressOrder.get(sortedImagesByAddressOrder.size() - 1).address);
		while (symbolSearchEnd > symbolSearch.getOffset()) {
			Symbol symbol = getSymbolAt(symbolSearch);
			if (symbol != null && (symbol.getSource() == SourceType.USER_DEFINED || symbol.getSource() == SourceType.IMPORTED) && !AUTO_PATTERN.matcher(symbol.getName()).matches() && (!imageSymbolNames.contains(symbol.getName()) || USED_EARLY_SYMBOLS.contains(symbol.getName()))) {
				boolean comesBeforeImages = symbol.getName().startsWith("MR") // Variables starting with the 'MR' prefix are in .lib files because the MR api is turned into .lib files.
					|| symbol.getName().startsWith("_") // Naming pattern, there are no variables which start with '_' in Frogger, but many in the runtime libraries do.
					|| LIB_SYMBOLS.contains(symbol.getName()) // .lib symbols are loaded before all objs.
					|| USED_EARLY_SYMBOLS.contains(symbol.getName()); // Used before sprdata.obj is linked.
				symbolsByAddressOrder.add(new HashedSymbol(symbol.getName(), symbol.getAddress(), comesBeforeImages));
			}
			
			symbolSearch = getSymbolAfter(symbolSearch).getAddress();
		}
		symbolsByAddressOrder.addAll(sortedImagesByAddressOrder);
		symbolsByAddressOrder.sort(Comparator.comparingLong(symbol -> symbol.address.getOffset()));
		
		int lastHash = -1; // Don't set to zero, because unless we have a symbol defined with zero, we don't know.
		List<HashedSymbol> seenHeaders = new ArrayList<>();
		for (int i = 0; i < symbolsByAddressOrder.size(); i++) {
			HashedSymbol symbol = symbolsByAddressOrder.get(i);
			
			if (symbol.hasHash()) {
				// Apply hashes to seen symbols.
				if (symbol.hash == lastHash) {
					for (HashedSymbol tempSymbol : seenHeaders)
						tempSymbol.hash = lastHash;
				} else if (!symbol.isFromLib && symbol.hasName() && !(symbol instanceof ImageHeader) && symbol.hash == lastHash + 1) {
					for (HashedSymbol tempSymbol : seenHeaders)
						tempSymbol.hash = lastHash;
				}
				
				// Ready for next.
				seenHeaders.clear();
				lastHash = symbol.hash;
				if (symbol.isFromLib)
					lastHash++;
			} else {
				seenHeaders.add(symbol);
			}
		}
		
		// Apply hashes for the final value.
		if (lastHash == SYMBOL_TABLE_SIZE - 1) {
			for (HashedSymbol tempSymbol : seenHeaders)
				tempSymbol.hash = lastHash;
			
			seenHeaders.clear();
		}
		
		// Generates BSS names.
		StringBuilder macroBuilder = new StringBuilder();
		if (GENERATE_BSS_NAMES) {
			HashSumLookupTree tree = buildTree();
			
			lastHash = -1;
			HashedSymbol lastSymbol = null;
			HashedSymbol lastNamed = null;
			List<HashedSymbol> symbolsSharingHash = new ArrayList<>();
			for (HashedSymbol symbol : symbolsByAddressOrder) {
				
				// Sanity Check.
				if (symbol.hasHash() && symbol.hasName() && lastHash > symbol.hash) {
					println("Incorrect hash for '" + symbol.name + "', expected >= " + lastHash + ", but got " + symbol.hash + ".");
					continue;
				}
				
				// Upon encountering symbol from library.
				// Does its hash match the last hash? If so, continue building the list. But, at the first non-lib symbol or lib symbol with hash that doesn't match, handle the group.
				// If the hash doesn't match, handle the previous group, but at the next non-lib symbol or symbol with hash, handle the new group.

				// Allows resetting, since we're only generating the image names, which follow predictable results with respect to isFromLib.
				boolean isReadyToResetFromLib = (lastSymbol != null && lastSymbol.isFromLib && lastSymbol.hasHash()) && !symbol.isFromLib;
				boolean encounteredNewHash = symbol.hasHash() && (symbol.hash != lastHash);
				
				if (encounteredNewHash || isReadyToResetFromLib) {
					int maxHash = isReadyToResetFromLib ? lastSymbol.hash : symbol.hash;
					int newHash = symbol.hasHash() ? symbol.hash : lastSymbol.hash + 1;

					if (!isReadyToResetFromLib && encounteredNewHash && !(symbol instanceof ImageHeader) && !symbol.isFromLib)
						maxHash = symbol.hash - 1; // The symbol we've encountered is exclusive, it we can't include it as a possibility.
					
					addMacrosForGroupSafely(tree, macroBuilder, symbolsSharingHash, lastHash, maxHash);
					symbolsSharingHash.clear();
					
					lastHash = newHash;
				}
				
				// Sanity checks. (Verify the provided labels are matching the rules we expect.)
				if (symbol.hasName()) {
					if (lastNamed != null && symbol.hash == lastNamed.hash) {
						String prevName = lastNamed.name;
						String currName = symbol.name;
						
						// Linker Hashing Tiebreaker - Use the reverse order from what the assembler outputs.
						boolean isCurrentImage = (symbol instanceof ImageHeader);
						boolean isLastImage = (lastNamed instanceof ImageHeader);
						
						int prevAssemblerHash = getAssemblerHash(prevName);
						int currAssemblerHash = getAssemblerHash(currName);
						
						if (!isLastImage) {
							// Current is image or symbol, last is symbol.
							if (lastNamed != null && lastNamed.isFromLib && isCurrentImage && isCurrentImage)
								throw new RuntimeException("Current image '" + symbol.name + "' is located after lib-symbol '" + lastNamed.name + "'.");
							
							if (lastNamed.address.getOffset() >= symbol.address.getOffset())
								throw new RuntimeException("Symbol '" + prevName + "' comes after '" + currName + "' when it should come before.");
						} else if (!isCurrentImage) {
							// Current is symbol, last is either image or symbol.
							
							// Violates the rules explained in isMacroOrderValid.
							if (!symbol.isFromLib || symbol.address.getOffset() <= lastNamed.address.getOffset())
								throw new RuntimeException("Symbol '" + currName + "' comes after '" + prevName + "', but it seems to be a symbol following an image..?");
						} else if (prevAssemblerHash == currAssemblerHash) {
							// Assembler Hashing Tiebreaker: Symbols are defined in the order which they are seen / referenced. (Not necessarily their declaration order)
									
							ImageHeader currImage = (ImageHeader) symbol;
							ImageHeader lastImage = (ImageHeader) lastNamed;
		
							// Both are images.
							int currTextureId = currImage.index;
							int lastTextureId = lastImage.index;
							if (lastTextureId <= currTextureId)
								throw new RuntimeException("Symbol '" + prevName + "' shares the same linker hash (" + symbol.hash + ") with '" + currName + "', but it its index (" + lastImage.index + ") comes after the current one (" + currImage.index + ")");
						} else {
							// Hashes do not match, so ensure order in the reverse order of the hash.
							if (currAssemblerHash > prevAssemblerHash && isCurrentImage) // curr must be < previous, because the order is reversed.
								throw new RuntimeException("Symbol '" + prevName + "' shares the same linker hash (" + symbol.hash + ") with '" + currName + "', but it its assembler hash (" + prevAssemblerHash + ") comes before the current one (" + currAssemblerHash + ")");
						}
					}
					
					lastNamed = symbol;
				}
				
				lastSymbol = symbol;
				symbolsSharingHash.add(symbol);
			}
			
			if (symbolsSharingHash.size() > 0) {
				addMacrosForGroupSafely(tree, macroBuilder, symbolsSharingHash, lastHash, SYMBOL_TABLE_SIZE);
				symbolsSharingHash.clear();
			}
			
			macroBuilder.append("\n");
		}
		
		// Prints the image table and remaps.
		StringBuilder sb = new StringBuilder();
		sb.append("MR_TEXTURE* bmp_pointers[] = {");

		for (int i = 0; i < unorderedImages.size(); i++) {
			ImageHeader header = unorderedImages.get(i);
			
			if (i % 16 == 0)
				sb.append("\n\t");
			
			sb.append(header.getDisplayName(true)).append(", ");
		}
		
		sb.append("\n};\n\n");		
		
		// Prints the images sorted.
		StringBuilder headerBuilder = new StringBuilder();
		for (HashedSymbol symbol : symbolsByAddressOrder) {
			if (symbol instanceof ImageHeader) {
				headerBuilder.append("MR_TEXTURE\t").append(symbol.getDisplayName(false)).append(";");
				
				if (DEBUG_HASHES && symbol.hasHash()) {
					headerBuilder.append(" // ").append(symbol.hash);
					if (!symbol.hasName())
						headerBuilder.append('*');
				}
				
			} else {
				if (!DEBUG_HASHES)
					continue;
				
				headerBuilder.append("// ").append(symbol.getDisplayName(false)).append(" (").append(symbol.hash).append(")");
			}
			
			headerBuilder.append("\n");
		}
		
		// Write to file.
		writeStringToFile("export.C", sb.toString() + headerBuilder.toString());
		writeStringToFile("texture-macros.h", macroBuilder.toString());
	}
	
	private void addMacrosForGroupSafely(HashSumLookupTree tree, StringBuilder builder, List<HashedSymbol> symbols, int minHash, int maxHash) {
		if (maxHash < minHash)
			throw new RuntimeException("Cannot generate macros for this group, the min hash (" + minHash + ") is greater than the max hash! (" + maxHash + ")");

		// Apply hashes if we can guarantee correctness.
		if (minHash == maxHash)
			for (HashedSymbol symbol : symbols)
				if (!symbol.hasHash())
					symbol.hash = minHash;
		
		if (!APPLY_HASHES_WHEN_UNSURE) {
			addMacrosForGroup(tree, builder, symbols, minHash, minHash);
			return;
		}
		
		for (int i = minHash; i <= maxHash; i++) {
			try {
				addMacrosForGroup(tree, builder, symbols, i, maxHash);
				return; // If it gets to this point, it was successfully completed.
			} catch (Throwable th) {
				if (i == maxHash)
					throw new RuntimeException("Couldn't add macros. (" + minHash + "->" + maxHash + ")", th);
			}
		}
	}
	
	private void addMacrosForGroup(HashSumLookupTree tree, StringBuilder builder, List<HashedSymbol> symbols, int minHash, int maxHash) {
		// Assumes: symbols is a list of headers containing all image headers which use the hash defined as 'hash'.
		// This hash may or may not be explicitly set, as long as we assume the goal is for them to use the given hash.
				
		// If applying hashes when we're unsure for certain is not enabled, we can only ensure order via this method if all of headers have either a valid name or a valid hash.
		// Otherwise, we'd be applying hashes when we're unsure, which is what the toggle is here to control.
		if (!APPLY_HASHES_WHEN_UNSURE)
			for (HashedSymbol symbol : symbols)
				if (!symbol.hasName() && !symbol.hasHash())
					return;
		
		// Ensure macro names are correct.
		int hash = minHash;
		HashedSymbol lastSymbol = null;
		String lastName = null;
		int lastAssemblerHash = -1;
		int lastLinkerHash = -1;
		boolean forceBestHash = false;
		for (int i = 0; i < symbols.size(); i++) {
			HashedSymbol symbol = symbols.get(i);
			ImageHeader currImage = (symbol instanceof ImageHeader) ? (ImageHeader) symbol : null;
			ImageHeader lastImage = (lastSymbol instanceof ImageHeader) ? (ImageHeader) lastSymbol : null;
			
			if (currImage != null)
				currImage.macroValue = null;
			
			try {
				String originalName = symbol.getDisplayName(false);
				String newDisplayName = originalName;
				
				// If the header doesn't have a name, or does not follow the expected order, generate a name.
				if (currImage != null && (!currImage.hasName() || !isMacroOrderValid(lastSymbol, currImage, lastName, newDisplayName))) {
					int tHash = currImage.hasHash() ? currImage.hash : hash;
					String autoPrefix = originalName + "_";
					
					// Generates a string with the highest assembly hash as possible, which is lower than the previous one.
					// If necessary, move to further modulos until null is reached.
					// If null is reached, use the largest option which gets as close to 255 as possible.
					int baseHash = getLinkerHashWithoutPrefix(autoPrefix, tHash);
					boolean canAssemblerHashMatchPrevious = ((lastImage != null) && (lastImage.index > currImage.index)) || (tHash > lastLinkerHash);
					
					int bestPossibleHash;
					if (lastAssemblerHash == -1 || tHash > lastLinkerHash) {
						bestPossibleHash = ASSEMBLER_TABLE_SIZE - 1;
					} else if (canAssemblerHashMatchPrevious) {
						bestPossibleHash = lastAssemblerHash;
					} else {
						bestPossibleHash = lastAssemblerHash - 1;
						if (bestPossibleHash < 0) // Skip this attempt, move on to the next one.
							throw new RuntimeException("Reached a hash which would need to be negative to be recreatable! (" + autoPrefix + ")");
					}
										
					String bestHashStr = getBestStringFromTree(tree, autoPrefix, bestPossibleHash, baseHash);
					String bestWorkingStr = generateWorkingString(tree, autoPrefix, bestPossibleHash, baseHash);
										
					if (bestHashStr != null && (!forceBestHash || bestWorkingStr == null)) {
						newDisplayName = autoPrefix + bestHashStr;
					} else if (bestWorkingStr != null) {
						newDisplayName = autoPrefix + bestWorkingStr;
					} else { // Failsafe.
						newDisplayName = autoPrefix + tree.generateString(autoPrefix, tHash);
					}
										
					int sanityCheckHash = getLinkerHash(newDisplayName);
					if (sanityCheckHash != tHash)
						throw new RuntimeException("Hash for '" + newDisplayName + "' was supposed to be " + currImage.hash + ", but it ended up being " + sanityCheckHash + ".");

					// Generate a name which results in the expected hash result.
					while (!isMacroOrderValid(lastSymbol, symbol, lastName, newDisplayName) && newDisplayName.length() <= MAX_SYMBOL_NAME_LENGTH)
						newDisplayName += HASH_OFFSET_PHRASE;
				}
			
				// Verify symbol name is still within the allowed length.
				if (newDisplayName.length() > MAX_SYMBOL_NAME_LENGTH)
					throw new RuntimeException("Symbol '" + originalName + "' has an expanded macro name which is too large, at " + newDisplayName.length() + " characters. ('" + newDisplayName + "')");

				if (!isMacroOrderValid(lastSymbol, symbol, lastName, newDisplayName))
					throw new RuntimeException("Symbol '" + newDisplayName + "' is not conforming to valid macro order. (Last: '" + lastName + "')");
				
				if (currImage != null && !newDisplayName.equals(originalName))
					currImage.macroValue = newDisplayName;
				
				lastSymbol = symbol;
				lastName = newDisplayName;
				lastAssemblerHash = getAssemblerHash(newDisplayName);
				lastLinkerHash = getLinkerHash(newDisplayName);
				forceBestHash = false;
			} catch (Throwable th) {
				if (hash == maxHash && forceBestHash)
					throw new RuntimeException(th);
				
				if (forceBestHash) {
					hash++;
					forceBestHash = false;
				} else {
					forceBestHash = true;
				}
				
				i--;
			}
		}
		
		// Write macros.
		for (int i = 0; i < symbols.size(); i++) {
			HashedSymbol symbol = symbols.get(i);
			if (!(symbol instanceof ImageHeader))
				continue;
			
			ImageHeader header = (ImageHeader) symbol;
			if (header.macroValue != null)
				builder.append("#define ").append(header.getDisplayName(false)).append(" ").append(header.macroValue).append("\n");
		}
	}
	
	private String getBestStringFromTree(HashSumLookupTree tree, String prefix, int bestPossibleHash, int baseHash) {
		int bestAssemblerHash = -1; // Target the hash with the highest value which is < (or possibly <=) the last seen one.
		int bestAssemblerLength = -1;
		HashSum bestHashSum = null;
		
		int prefixHash = getLinkerHash(prefix);
		
		int moduloIncrement = 0;
		HashSum foundSum = tree.get(baseHash);
		while (foundSum != null) {
			int[] lengths = foundSum.stringLengths.getFlags();
			for (int j = 0; j < lengths.length; j++) {
				int length = lengths[j];
				int fullLength = length + prefix.length();
														
				// Gets the assembler hash of the full string. Must be the full string because we're comparing against other full hashes.
				int assemblerHash = convertLinkerHashToAssemblerHash(prefixHash + foundSum.sum, fullLength);
				if (assemblerHash > bestAssemblerHash && bestPossibleHash >= assemblerHash)	{					
					bestAssemblerHash = assemblerHash;
					bestAssemblerLength = length;
					bestHashSum = foundSum;
				}
			}
			
			foundSum = tree.get(baseHash + (SYMBOL_TABLE_SIZE * ++moduloIncrement));
		}
		
		return bestHashSum != null ? bestHashSum.generateString(bestAssemblerLength) : null;
	}
	
	private String generateWorkingString(HashSumLookupTree tree, String prefix, int targetAssemblerHash, int baseLinkerHash) {	
		
		int moduloIncrement = 0;
		int prefixHash = getLinkerHash(prefix);
		HashSum foundSum = tree.get(baseLinkerHash);
		while (foundSum != null) {
			int[] lengths = foundSum.stringLengths.getFlags();
			for (int j = 0; j < lengths.length; j++) {
				int length = lengths[j];
				int fullLength = length + prefix.length();
				int assemblerHash = convertLinkerHashToAssemblerHash(prefixHash + foundSum.sum, fullLength);
				
				if (targetAssemblerHash == assemblerHash)
					return foundSum.generateString(length);
				
				int distance = targetAssemblerHash > assemblerHash
					? (targetAssemblerHash - assemblerHash)
					: (targetAssemblerHash + (ASSEMBLER_TABLE_SIZE - assemblerHash));
				
				for (int i = 0; i < LINKER_HASH_OFFSET_PHRASES.length; i++) {
					String offsetPhrase = LINKER_HASH_OFFSET_PHRASES[i];
					if ((distance % offsetPhrase.length()) == 0) {
						StringBuilder builder = new StringBuilder(foundSum.generateString(length));
						while (distance > 0) {
							builder.append(offsetPhrase);
							distance -= offsetPhrase.length();
						}
						
						return builder.toString();
					}
				}
			}
			
			foundSum = tree.get(baseLinkerHash + (SYMBOL_TABLE_SIZE * ++moduloIncrement));
		}
		
		return null;
	}
	
	private boolean isMacroOrderValid(HashedSymbol lastSymbol, HashedSymbol currSymbol, String lastName, String currName) {
		if (lastSymbol == null || lastName == null)
			return true; // If there is no last header, then the order must be correct as this is the first header, and thus, there is no order.
				
		// Check #1 - Is the linker hash >= the last one?
		int currLinkerHash = getLinkerHash(currName);
		int lastLinkerHash = getLinkerHash(lastName);
		if (lastLinkerHash > currLinkerHash) {
			return false;
		} else if (lastLinkerHash < currLinkerHash) {
			return true;
		}
		
		// Reached Reverse Assembler Obj Order
		// Check #2 - Link Order. (Textures are linked before bss stuff)
		// The linker loads objs in the order which they are linked.
		// The .bss symbols are added to a hash table, ordered, based on the insertion order, which is the reverse of the order they are found in .obj files.
		// 'sprdata.obj' is very early for Frogger, coming before any other BSS symbols.
		// So, if we see a non-texture symbol, it means it will be seen later than the texture symbols in the .obj files.
		// Because this is reversed, it means other symbols always appear before textures in the final order.
		
		boolean isCurrentImage = (currSymbol instanceof ImageHeader);
		boolean isLastImage = (lastSymbol instanceof ImageHeader);
		
		if (!isLastImage) {
			// Current is image, last is symbol, or both are symbol.
			
			if (lastSymbol != null && lastSymbol.isFromLib && isCurrentImage) { // Should never occur, so it is printed as well as thrown (since thrown errors are interpretted as needing to try another combo.)
				String errMsg = "Current image '" + currSymbol.name + "' is located after lib-symbol '" + lastSymbol.name + "'.";
				println(errMsg);
				throw new RuntimeException(errMsg);
			}
			
			// Example of this working: 'im_swp1pic' > 'Frogs'.
			return currSymbol.address.getOffset() > lastSymbol.address.getOffset();
		} else if (!isCurrentImage) {
			// Current is symbol, last is image.
			
			if (currSymbol.isFromLib && currSymbol.address.getOffset() > lastSymbol.address.getOffset())
				return true;
			
			// We throw an error here. This is because we want the list of symbols to be in order by address.
			// If the last symbol's address is greater than the current one, that means the symbol list is not sorted.
			// But, if this symbol's address is greater than the last one, then we're violating how the hash works (since objs linked after sprdata.obj should have their symbols placed before image symbols.)
			String errMsg = "The current symbol is an image, yet the previous one is not. Error? (Last: " + lastSymbol.name + "/" + lastSymbol.address + ", Curr: " + currSymbol.name + "/" + currSymbol.address + ")";
			println(errMsg);
			throw new RuntimeException(errMsg);
		}
		
		// Beyond this point, both symbols must be images, due to the above checks.
		ImageHeader currImage = (ImageHeader) currSymbol;
		ImageHeader lastImage = (ImageHeader) lastSymbol;
		
		// Reached Reverse Assembler Obj Order
		// Check #3 - Assembler Hashes
		int currAssemblerHash = getAssemblerHash(currName);
		int lastAssemblerHash = getAssemblerHash(lastName);
		if (currAssemblerHash > lastAssemblerHash) {
			return false; // Reverse order is used.
		} else if (currAssemblerHash < lastAssemblerHash) {
			return true;
		}
		
		// Check #4 - Texture IDs.
		// The order in which sprdata.obj has textures is sorted by texture id, lowest to highest (after hashing ofc).
		// Due to reversing, we ensure the last texture id is greater than the current one.
		int currTextureId = currImage.index;
		int lastTextureId = lastImage.index;
		return lastTextureId > currTextureId;
	}
	
	private void writeStringToFile(String fileName, String data) throws java.io.IOException {
		List<String> lines = new ArrayList<>();
		for (String line : data.split("\n"))
			lines.add(line);
		
		Files.write(new File(fileName).toPath(), lines);
	}
	
	private class ImageHeader extends HashedSymbol {
		public String macroValue;
		public int index;
		
		public ImageHeader(String name, Address address, int index) {
			super(name, address, false);
			this.macroValue = null;
			this.index = index;
		}
		
		
		@Override
		public String getDisplayName(boolean reference) {
			if (this.address == null || this.address.getOffset() == 0)
				return "NULL";
			if (hasName())
				return (reference ? "&" : "") + this.name;
			return (reference ? "&" : "") + "im_img" + this.index;
		}
	}
	
	private class HashedSymbol {
		public String name;
		public Address address;
		public int hash;
		public boolean isFromLib;
		
		public HashedSymbol(String name, Address address, boolean isFromLib) {
			this.name = name;
			this.address = address;
			this.hash = hasName() ? getLinkerHash(name) : -1;
			this.isFromLib = isFromLib;
		}
		
		public boolean hasHash() {
			return this.hash >= 0 && this.hash < SYMBOL_TABLE_SIZE;
		}
		
		public boolean hasName() {
			return this.name != null;
		}
		
		public String getDisplayName(boolean reference) {
			if (this.address == null || this.address.getOffset() == 0)
				return "NULL";
			if (hasName())
				return (reference ? "&" : "") + this.name;
			throw new RuntimeException("Cannot get name of symbol which doesn't have name. (At: " + this.address + ")");
		}
	}
	
	//////////////////////////////////////////////////////////////////
	////				IMAGE NAME GENERATOR					  ////
	////														  ////
	//// All code beyond here is used for the generation		  ////
	////  of fake image names. This is based on the linker		  ////
	////  sorting symbols in '.bss' by a hash. So we generate	  ////
	////  names which satisfy the hashing algorithm.			  ////
	//////////////////////////////////////////////////////////////////
	
	private int getLinkerHash(String symbolName) {
		// Restrictions:
		// - Symbol is <= 255 bytes long. This is because the linker only uses storage of one byte for the size of the symbol name string.
		// - Symbols contain: [_, a-Z, A-Z, 0-9], start with im_.
		
		return getFullLinkerHash(symbolName) % SYMBOL_TABLE_SIZE; // (hash & 0x1FF);
	}
	
	private int getAssemblerHash(String symbolName) {
		// Restrictions:
		// - Symbol is <= 255 bytes long. This is because the linker only uses storage of one byte for the size of the symbol name string.
		// - Symbols contain: [_, a-Z, A-Z, 0-9], start with im_.
		
		return getFullAssemblerHash(symbolName) % ASSEMBLER_TABLE_SIZE;
	}
	
	private int convertLinkerHashToAssemblerHash(int linkerHash, int strLength) {
		int assemblerHash = linkerHash - strLength;
		while (assemblerHash < 0)
			assemblerHash += ASSEMBLER_TABLE_SIZE;
		return assemblerHash % ASSEMBLER_TABLE_SIZE;
	}
	
	// Image Name Generator:
	private static final int SYMBOL_TABLE_SIZE = 512;
	private static final int ASSEMBLER_TABLE_SIZE = 256;
	private static final int MAX_SYMBOL_NAME_LENGTH = 255;
	private static final char MAX_ALLOWED_CHARACTER;

	private static final int PASS_COUNT = 5;
	private static final char[] ALLOWED_NAME_CHARACTERS = { // This table must be sorted.
		'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', // 48 -> 57, 95.
		'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '_',
		'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
	};
	
	// This string has a hash of zero. It can be used to make a string longer (for sorting tiebreaker) without changing the hash.
	private static final String HASH_OFFSET_PHRASE = "_Yah0I"; // Options: "Yaahx", "_Yah0I"
	private static final String[] LINKER_HASH_OFFSET_PHRASES = {"_dare", "_Yah0I", "0000Ezz", "000000_y", "00000004s", "00000004A1"};
	
	static {
		char maxChar = 0;
		for (char allowedNameCharacter : ALLOWED_NAME_CHARACTERS)
			if (allowedNameCharacter > maxChar)
				maxChar = allowedNameCharacter;

		MAX_ALLOWED_CHARACTER = maxChar;
	}
	
	// All symbols in the 'bss' section get ordered by this hash function.
	// Performs the hash function done in 'psylink.exe' found in PsyQ 4.0. Function: 0x0040614f
	// Collisions are handled:
	//   1) Using the reverse order from how they are inserted. In other words, the reverse order from the input .obj file.
	// Since Frogger provides '/c', making it a case-sensitive link, the string is hashed directly. If it did not have this flag, it would use the upper-case letters for hashing.
	private int getFullLinkerHash(String input) {
		int hash = input.length();
		for (int i = 0; i < input.length(); i++)
			hash += input.charAt(i);
		
		return hash;
	}
	
	// All symbols in the 'bss' section get ordered by the linker's output order as the last tiebreaker.
	// However, the assembler's .obj output is used by the linker when hash collisions occur.
	// Performs the hash function done in 'aspsx.exe' found in PsyQ 4.0. Function: 0x00401fa7
	// Collisions are handled:
	//   1) Symbols are defined in the order which they are seen / referenced. (Not necessarily their declaration order)
	//      This ends up working out nicely for us, because this order is the textures, ordered by their ID.
	private int getFullAssemblerHash(String input) {
		int hash = 0;
		for (int i = 0; i < input.length(); i++)
			hash += input.charAt(i);
		
		return hash;
	}
	
	private int getLinkerHashWithoutPrefix(String prefix, int fullHash) {
		int result = fullHash - getFullLinkerHash(prefix);
		while (result < 0)
			result += SYMBOL_TABLE_SIZE;
		return result;
	}
	
	private boolean isSorted(String input) {
		for (int i = 1; i < input.length(); i++)
			if (input.charAt(i - 1) > input.charAt(i))
				return false;
		return true;
	}
	
	private HashSumLookupTree buildTree() {
		HashSumLookupTree newTree = new HashSumLookupTree();

		// Create the basic characters used to generate the rest. (Pass #1)
		for (char character : ALLOWED_NAME_CHARACTERS) {
			HashSum newNode = newTree.getOrCreate(character + 1);
			newNode.stringLengths.set(1, true); // Set the length as only able to be 1.
		}

		Map<Integer, Set<HashSumPair>> additionsThisPass = new HashMap<>();
		for (int pass = 1; pass < PASS_COUNT; pass++) {
			long passStart = System.currentTimeMillis();

			// Setup additions for this pass.
			for (HashSum sumOne : newTree.allSums) {
				for (HashSum sumTwo : newTree.allSums) {
					int newSum = sumOne.sum + sumTwo.sum;
					additionsThisPass.computeIfAbsent(newSum, key -> new HashSet<>()).add(new HashSumPair(sumOne, sumTwo));
				}
			}

			// Apply additions from this pass.
			int[] firstLength = new int[MAX_SYMBOL_NAME_LENGTH];
			int[] secondLength = new int[MAX_SYMBOL_NAME_LENGTH];
			for (Entry<Integer, Set<HashSumPair>> entry : additionsThisPass.entrySet()) {
				HashSum newNode = newTree.getOrCreate(entry.getKey());
				
				for (HashSumPair pair : entry.getValue()) {
					if (!newNode.pairs.add(pair))
						continue; // Already present somehow?
					
					int firstCount = pair.first.stringLengths.getFlags(firstLength);
					int secondCount = pair.second.stringLengths.getFlags(secondLength);
					
					for (int i = 0; i < firstCount; i++) {
						for (int j = 0; j < secondCount; j++) {
							int newLength = firstLength[i] + secondLength[j];
							newNode.stringLengths.set(newLength, true);
							newNode.lengthPairs.put(newLength, pair);
						}
					}
				}
				
				entry.getValue().clear();
			}
			
			long passEnd = System.currentTimeMillis();
			println("Pass #" + (pass + 1) + " took " + (passEnd - passStart) + " ms. (" + newTree.allSums.size() + ")");
		}
		
		return newTree;
	}
	
	public class HashSumLookupTree {
		private final List<HashSum> sums = new ArrayList<>();
		public final List<HashSum> allSums = new ArrayList<>();

		public HashSum get(int sum) {
			if (sum < 0 || sum >= this.sums.size())
				return null;
			return this.sums.get(sum);
		}

		public HashSum getOrCreate(int sum) {
			if (sum < 0)
				throw new RuntimeException("Cannot add sum less than zero.");
			while (sum >= this.sums.size())
				this.sums.add(null);

			HashSum hashSum = this.sums.get(sum);
			if (hashSum == null) {
				this.sums.set(sum, hashSum = new HashSum(sum));
				this.allSums.add(hashSum);
			}
			return hashSum;
		}

		public String generateString(String prefix, int realHash) {
			int prefixHash = getFullLinkerHash(prefix);
			int totalHashCount = ((MAX_SYMBOL_NAME_LENGTH * (MAX_ALLOWED_CHARACTER + 1)) / SYMBOL_TABLE_SIZE) + 1;

			for (int i = 0; i < totalHashCount; i++) {
				int fullTargetHash = (realHash + (i * SYMBOL_TABLE_SIZE)) - prefixHash; // The efficient way to deal with the prefix is subtraction, since the lower the target number, the more eliminated options from the start. Less complex too.
				if (fullTargetHash < 0)
					continue;

				HashSum hashSum = this.get(fullTargetHash);
				if (hashSum != null)
					return hashSum.generateString();
			}

			throw new RuntimeException("Couldn't generate name for prefix '" + prefix + "', and hash: " + realHash + ". (Try increasing the pass count.)");
		}
	}
	
	public class HashSum {
		public final int sum;
		public final Set<HashSumPair> pairs;
		public final FlagTracker stringLengths;
		private final Map<Integer, HashSumPair> lengthPairs = new HashMap<>();
		private final Map<Integer, String> cachedStrings = new HashMap<>();
		private String cachedString;
		
		public HashSum(int sum) {
			this.sum = sum;
			this.pairs = new HashSet<>();
			this.stringLengths = new FlagTracker(MAX_SYMBOL_NAME_LENGTH);
		}

		@Override
		public int hashCode() {
			return this.sum;
		}

		@Override
		public boolean equals(Object object) {
			return (object instanceof HashSum) && ((HashSum) object).sum == this.sum;
		}
		
		public String generateString(int length) {
			String cachedStr = this.cachedStrings.get(length);
			if (cachedStr != null)
				return cachedStr;
			
			if (!this.stringLengths.get(length))
				throw new RuntimeException("Cannot generate string from HashSum " + this.sum + " of length " + length + ".");
			
			String result;
			if (length == 1) {
				result = String.valueOf((char)(this.sum - 1));
			} else {
				HashSumPair parentPair = this.lengthPairs.get(length);
				
				int[] firstLengths = parentPair.first.stringLengths.getFlags();
				int[] secondLengths = parentPair.second.stringLengths.getFlags();
				
				result = null;
				for (int i = 0; i < firstLengths.length; i++) {
					int firstLength = firstLengths[i];
					if (firstLength >= length)
						continue; // First length too large.
					
					int secondLengthIndex = Arrays.binarySearch(secondLengths, length - firstLength);
					if (secondLengthIndex < 0)
						continue;
					
					int secondLength = secondLengths[secondLengthIndex];
					result = parentPair.first.generateString(firstLength) + parentPair.second.generateString(secondLength);
					break;
				}
				
				if (result == null)
					throw new RuntimeException("Cannot generate string from HashSum " + this.sum + " of length " + length + ", no pairs added up...");
			}
			
			this.cachedStrings.put(length, result);
			return result;
			
		}
		
		public String generateString() {
			if (this.cachedString != null)
				return this.cachedString;
			
			String result;
			if (this.pairs.size() == 0) {
				result = String.valueOf((char)(this.sum - 1));
			} else {
				String bestString = null;
				for (HashSumPair pair : this.pairs) {
					int newLength = pair.first.generateString().length() + pair.second.generateString().length();
					if (bestString == null || bestString.length() > newLength)
						bestString = pair.first.generateString() + pair.second.generateString();
				}
				
				result = bestString;
			}
			
			return this.cachedString = result;
		}
	}
	
	public class HashSumPair {
		public HashSum first;
		public HashSum second; 

		public HashSumPair(HashSum first, HashSum second) {
			this.first = first;
			this.second = second;
		}

		@Override
		public int hashCode() {
			return (this.first.sum - this.second.sum) * this.first.sum * this.second.sum;
		}

		@Override
		public boolean equals(Object object) {
			return (object instanceof HashSumPair)
					&& ((HashSumPair) object).first.equals(this.first)
					&& ((HashSumPair) object).second.equals(this.second);
		}
	}
	
	private static int[] CACHE_FLAG_ARRAY = new int[128];
	public class FlagTracker {
		private byte[] bytes;
		private int minFlag = -1;
		private int maxFlag = -1;
		private int flagCount = 0;
		private int maxFlagCount = 0;
		
		public FlagTracker(int numOfFlags) {
			// Expand cache array so it can hold it.
			if (numOfFlags > CACHE_FLAG_ARRAY.length) {
				int newSize = CACHE_FLAG_ARRAY.length * 2;
				while (numOfFlags > newSize)
					newSize *= 2;
				CACHE_FLAG_ARRAY = new int[newSize];
			}
			
			this.maxFlagCount = numOfFlags;
			this.bytes = new byte[(numOfFlags / 8) + (numOfFlags % 8 > 0 ? 1 : 0)];
		}
		
		public int getMinFlag() {
			return this.minFlag;
		}
		
		public int getMaxFlag() {
			return this.maxFlag;
		}
		
		public int getActiveFlagCount() {
			return this.flagCount;
		}
		
		public int getFlagSlotCount() {
			return this.maxFlagCount;
		}
		
		public void set(int flag, boolean newState) {
			if (flag < 0 || flag >= this.maxFlagCount)
				throw new RuntimeException("The flag " + flag + " is outside the range of tracked flags.");
			
			boolean oldState = get(flag);
			if (oldState == newState)
				return;
			
			int index = flag / 8;
			int bit = flag % 8;
			if (newState) {
				this.bytes[index] |= (1 << bit);
				this.flagCount++;
				
				if (flag > this.maxFlag || this.maxFlag == -1)
					this.maxFlag = flag;
				if (flag < this.minFlag || this.minFlag == -1)
					this.minFlag = flag;
			} else {
				this.bytes[index] &= ~(1 << bit);
				this.flagCount--;
				
				if (flag == this.maxFlag) {
					this.maxFlag = -1;
					
					// Reduce to the highest value, if one exists.
					if (this.flagCount > 0)
						for (int i = flag; i >= this.minFlag && this.maxFlag == -1; i--)
							if (this.get(i))
								this.maxFlag = i;
				}
				
				if (flag == this.minFlag) {
					this.minFlag = -1;
					
					// Reduce to the highest value, if one exists.
					if (this.flagCount > 0)
						for (int i = flag; i <= this.maxFlag && this.minFlag == -1; i++)
							if (this.get(i))
								this.minFlag = i;
				}
			}
		}
		
		public boolean get(int flag) {
			if (flag < 0 || flag >= this.maxFlagCount)
				return false;
			
			int index = flag / 8;
			int bit = flag % 8;
			return (this.bytes[index] & (1 << bit)) == (1 << bit);
		}
		
		public int getFlags(int[] array) {
			Arrays.fill(array, -1);
			if (this.flagCount == 0)
				return 0;
			
			int count = 0;
			for (int i = this.minFlag; i <= this.maxFlag; i++)
				if (this.get(i))
					array[count++] = i;
			
			return count;
		}
		
		public int[] getFlags() {
			int count = this.getFlags(CACHE_FLAG_ARRAY);
			int[] newArray = new int[count];
			System.arraycopy(CACHE_FLAG_ARRAY, 0, newArray, 0, count);
			return newArray;
		}
	}
	
}