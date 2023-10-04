// Contains utilities for parsing headers and applying it to Ghidra projects. Kinda jank.
//@author Kneesnap
//@category Data Types
//@keybinding
//@menupath
//@toolbar

// Adapted from https://github.com/fmagin/ghidra_scripts/blob/master/ParseDataType.java,
// I have upgraded this script to more or less allow use to give ghidra a source code directory, and it will parse all .C / .H files and import the structs.
// It will also generate a context header file for decomp projects & decomp.me, although this is kinda jank.

// NOTE: Any structs which use defines for stuff like array indices do not work properly right now. See if we can include those defines.

import docking.DialogComponentProvider;
import ghidra.app.script.GhidraScript;
import ghidra.app.util.cparser.C.CParser;
import ghidra.app.util.cparser.C.ParseException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.Union;
import ghidra.program.model.data.Enum;
import ghidra.program.model.data.Array;
import ghidra.program.model.data.Pointer;
import ghidra.program.model.data.TypeDef;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.Composite;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.AbstractIntegerDataType;
import ghidra.program.model.data.FunctionDefinition;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.BuiltInDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.data.AbstractFloatDataType;
import ghidra.program.model.data.AbstractStringDataType;
import ghidra.program.model.data.ParameterDefinition;
import ghidra.program.model.data.Undefined;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionSignature;
import ghidra.program.model.symbol.SourceType;
import ghidra.app.cmd.function.ApplyFunctionSignatureCmd;
import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.util.parser.FunctionSignatureParser;
import ghidra.program.model.lang.RegisterValue;

import java.lang.Throwable;
import javax.swing.*;
import java.util.*;
import java.lang.RuntimeException;
import java.lang.StringBuilder;
import java.io.*;
import java.nio.file.Files;
import java.math.BigInteger;


public class ParseDataTypesFromCode extends GhidraScript {
    private static final Set<String> FILES_TO_SKIP = new HashSet<>(Arrays.asList(            
            "Unused", "PC", "Helpful Files", "old")); 
    
    private static final Set<String> IFDEF_FLAGS = new HashSet<>(Arrays.asList(
            "BUILD_RELEASE", "BUILD_CD_RESOURCES", 
            "PSX_SOUND", "PSX_ENABLE_XA", 
            
            // PSX:
            "USE_FASTSTACK", "PSX_CD_LOAD",
            "PSX_CD_STREAMS",
            "__psx", "PSX",
			"MR_KEEP_SYSTEM_RAND", "MR_KEEP_SYSTEM_RSIN", "MR_KEEP_SYSTEM_RCOS"
            
            // PC:
            //"WIN95", "WIN95_CD_LOAD"
            
            ));
            
    private static final Set<String> FLAGS_BOTH = new HashSet<>(Arrays.asList(
            "__MR_ONLY_INCLUDE_TYPEDEFS"));
            
    private static final long GP_REGISTER = 0x800c9780L; // Frogger Build 50b.
    
    @Override
    protected void run() throws Exception {
        var dialog = new ParseStructDialog();
        state.getTool().showDialog(dialog);
    }


    class ParseStructDialog extends DialogComponentProvider {
            private final DataTypeManager main_gdt;
            private JTextArea textInput;
            JTextArea typeOutput;
            
            private ParsedCode fullCode;
            private List<DataType> parsedTypes = new ArrayList<>();
            private Address functionAddress;
    
            JScrollPane inputScroll;
            JScrollPane outputScroll;
            JButton bulkButton;
            JButton parseButton;
            JButton applyFunctionButton;
    
            JSplitPane splitter;
            private ParseStructDialog() {
                super("Parse Data Type", false, true, true, true);
                setPreferredSize(500, 400);
                
                this.functionAddress = currentAddress;
   
    
                // GUI SETUP
                this.addCancelButton();
                
                this.bulkButton = new JButton("Parse Directory");
                this.bulkButton.addActionListener(e -> this.parseCodeFromFolder());
                this.bulkButton.setToolTipText("Parse all the source code in a directory.");
                this.addButton(bulkButton);
                
                this.applyFunctionButton = new JButton("Apply Function");
                this.applyFunctionButton.addActionListener(e -> this.applyFunctionToCursor());
                this.applyFunctionButton.setToolTipText("Applies the function to the cursor.");
                this.applyFunctionButton.setEnabled(false);
                this.addButton(applyFunctionButton);
                
                this.parseButton = new JButton("Parse");
                this.parseButton.addActionListener(e -> this.parseType());
                this.parseButton.setToolTipText("Parse the type and preview the result");
                this.addButton(parseButton);
    
                this.addApplyButton();
                this.setApplyToolTip("Add the last parsed type to the current data types");
                this.setApplyEnabled(false);
    
                textInput = new JTextArea(12, 50);
                textInput.setWrapStyleWord(true);
                textInput.setLineWrap(true);
                textInput.setText("struct Example {\n\tint exampleInt;\n\tvoid* exampleVoidPtr;\n};");
    
                typeOutput = new JTextArea(12, 50);
                typeOutput.setWrapStyleWord(true);
                typeOutput.setLineWrap(true);
                typeOutput.setEditable(false);
                
                inputScroll = new JScrollPane(textInput);
                outputScroll = new JScrollPane(typeOutput);
    
                splitter = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT,
                        inputScroll, outputScroll);
    
                addWorkPanel(splitter);
    
                // Parser Setup
                main_gdt = currentProgram.getDataTypeManager();
            }
            
            private void applyFunctionToCursor() {
                Function startFunction = getFunctionAt(this.functionAddress);
                if (startFunction == null) {
                    popup("No function exists at the cursor's position.");
                    return;
                }
                
                String functionName;
                try {
                    functionName = askString("Function Pls (For " + this.functionAddress + ")", "Please enter the name of the function to apply.");
                } catch (Throwable th) {
                    return;
                }
                
                
                start();
                
                FunctionSignatureParser parser = new FunctionSignatureParser(main_gdt, null);
                
                StringBuilder builder = new StringBuilder();
                String testName1 = " " + functionName + "(";
                String testName2 = " " + functionName + " (";
                Address tempFunctionAddr = startFunction.getEntryPoint();
                String foundSource = null;
                for (FunctionImplSignature signatureSrc : fullCode.FunctionSignatures) {
                    String signatureContents = signatureSrc.getContents();
                    
                    if (foundSource == null) {
                        if (signatureContents.contains(testName1) || signatureContents.contains(testName2)) {
                            foundSource = signatureSrc.Source;
                        } else {
                            continue;
                        }
                    }
                    
                    if (!foundSource.equals(signatureSrc.Source))
                        break; // Done.
                    
                    Function function = getFunctionAt(tempFunctionAddr);
                    if (function == null) {
                        runCommand(new DisassembleCommand(tempFunctionAddr, null, true));
                        function = createFunction(tempFunctionAddr, "TemporaryFunction");
                        
                        if (GP_REGISTER != 0 && GP_REGISTER != -1) {
                            try {
                                currentProgram.getProgramContext().setRegisterValue(function.getBody().getMinAddress(), function.getBody().getMaxAddress(), new RegisterValue(currentProgram.getRegister("gp"), BigInteger.valueOf(GP_REGISTER)));
                            } catch (Throwable th) {
                                println("Failed to update $gp register for new function.");
                            }
                        }
                    }
                    
                    FunctionSignature signature;
                    try {
                        signature = parser.parse(null, signatureContents);
                    } catch (Throwable th) {
                        end(false);
                        throw new RuntimeException("There was an error parsing the function signature '" + signatureContents + "' for the function at " + tempFunctionAddr + ".", th);
                    }
                    
                    runCommand(new ApplyFunctionSignatureCmd(tempFunctionAddr, signature, SourceType.IMPORTED, false, true));
                    builder.append(function.getName() + "@" + function.getEntryPoint() + "\n");
                    
                    // Move to end of function.
                    tempFunctionAddr = function.getBody().getMaxAddress().next();
                }
                
                end(true);
                this.functionAddress = tempFunctionAddr;
                
                typeOutput.setText(builder.toString());
                if (foundSource == null) {
                    popup("No function named '" + functionName + "' could be found.");
                } else {
                    popup("Done!");
                }
            }
    
            private void parseType() {
                fullCode = parseCode(this.textInput.getText(), "Text Box");
                parseTypes(null, fullCode.DataTypeDefinitions, fullCode);
            }
            
            private void parseCodeFromFolder() {
                
                File folder;
                try {
                    folder = askDirectory("Please choose the directory to recursively import structs from.", "Go!");
                    if (folder == null)
                        return;
                } catch (ghidra.util.exception.CancelledException cancelledException) {
                    return;
                }
                
                List<File> foundFiles = new ArrayList<>();
                List<File> fileQueue = new ArrayList<>();
                fileQueue.add(folder);
                
                fullCode = new ParsedCode();
                
                while (fileQueue.size() > 0) {
                    File directory = fileQueue.remove(fileQueue.size() - 1);
                    
                    for (File file : directory.listFiles()) {
                        if (FILES_TO_SKIP.contains(file.getName().replace("/", "")))
                            continue; // Skip files which should be skipped.
                        
                        if (file.isDirectory()) {
                            fileQueue.add(file);
                        } else if (file.isFile()) {
                            String name = file.getName().toLowerCase();
                            if (name.endsWith(".c") || name.endsWith(".h") || name.endsWith(".cpp") || name.endsWith(".hpp"))
                                foundFiles.add(file);
                        }
                    }
                }
                
                PrintWriter writer;
                PrintWriter writerSorted;
                
                try {
                    writer = new PrintWriter(new File(folder.getParentFile(), "raw-parsed-data.H"));
                    writerSorted = new PrintWriter(new File(folder.getParentFile(), "raw-parsed-data-ordered.H"));
                } catch (FileNotFoundException ex) {
                    throw new RuntimeException("Can't create output writer.", ex);
                }
                
                // Main writer.
                for (File file : foundFiles) {
                    try {
                        List<String> fileLines = Files.readAllLines(file.toPath());
                        ParsedCode parsedCode = parseCode(fileLines, file.getName());
                        
                        fullCode.addChunks(parsedCode);
                                            
                        writer.write("///### " + file.getName() + ":\n");
                        for (DataChunk chunk : parsedCode.AllChunks)
                            writer.write(chunk.getContents() + "\n");
                        writer.write("\n\n");
                    } catch (IOException ex) {
                        throw new RuntimeException("Failed to read " + file, ex);
                    }
                }
                
                // Write macros.
                for (ParsedMacro macro : fullCode.Macros.values()) {
                    writerSorted.append(macro.getContents());
                    writerSorted.append("\n");
                }
                writerSorted.append("\n\n");
                
                writer.close();
                
                // Parse types.
                this.applyFunctionButton.setEnabled(true);
                parseTypes(writerSorted, fullCode.DataTypeDefinitions, fullCode);
                writerSorted.write("\n\n");
                
                // Write externs.
                for (ExternDefinition extern : fullCode.Externs) {
                    writerSorted.append(extern.getContents());
                    writerSorted.append("\n");
                }
                if (fullCode.Externs.size() > 0)
                    writerSorted.write("\n\n");
                
                // Write functions.
                for (FunctionImplSignature func : fullCode.FunctionSignatures) {
                    writerSorted.append(func.getContents());
                    writerSorted.append(";\n");
                }
                if (fullCode.FunctionSignatures.size() > 0)
                    writerSorted.write("\n\n");
                
                // Finish writing.
                writerSorted.close();
            }
    
            @Override
            protected void applyCallback() {
                Set<String> newDataTypes = new HashSet<String>();
                
                int transaction_id = main_gdt.startTransaction("Parsed");
                try {
                    List<DataType> existingTypes = new ArrayList<>();
                    
                    for (DataType currentType : this.parsedTypes) {
                        if (currentType instanceof TypeDef && currentType.getName().equals(((TypeDef) currentType).getBaseDataType().getName() + " *"))
                            continue;
                        
                        existingTypes.clear();
                        main_gdt.findDataTypes(currentType.getName(), existingTypes, true, TaskMonitor.DUMMY);
                        
                        existingTypes.removeIf(type -> !currentType.getName().equals(type.getName())); // For example, double pointers are returned by the findDataTypes method, even if the string you supply only is single poitner.
                        if (existingTypes.size() > 0 && (currentType instanceof TypeDef || currentType instanceof Pointer || currentType instanceof Array))
                            continue; // If this is a typedef, and one already exists with this name, just skip, because this doesn't provide any value.
                        
                        if (existingTypes.size() == 0 || newDataTypes.add(currentType.getName())) { // Allows replacing existing data types from before this execution instance.                        
                            
                            if (existingTypes.size() == 1) {
                                // addDataType seems to silently fail sometimes, so we'll deal with this instead.
                                this.replaceDataType(existingTypes.get(0), currentType);
                            } else {
                                main_gdt.addDataType(currentType, DataTypeConflictHandler.REPLACE_HANDLER);
                            }
                            continue;
                        }
                        
                        if (existingTypes.size() > 1)
                            throw new RuntimeException("There are "  + existingTypes.size() + " data types named '" + currentType.getName() + "'.");
                                                
                        DataType existingType = existingTypes.get(0);
                        
                        // If the existing type is typedef, and this one is not,  replace!
                        if (existingType instanceof TypeDef) {
                            this.replaceDataType(existingType, currentType);
                        } else if (currentType instanceof Enum) {
                            if (!(existingType instanceof Enum))
                                throw new RuntimeException("The existing '" + existingType.getName() + "' type was not an enum? Was: " + existingType.getClass().getSimpleName() + ".");
                            
                            Enum newEnumType = (Enum)currentType;
                            Enum oldEnumType = (Enum)existingType;
                            if (newEnumType.getCount() > oldEnumType.getCount())
                                this.replaceDataType(oldEnumType, newEnumType);
                        } else if (currentType instanceof Composite) {
                            if (!(existingType instanceof Composite))
                                throw new RuntimeException("The existing '" + existingType.getName() + "' type was not a struct/union/Composite? Was: " + existingType.getClass().getSimpleName() + ".");
                            
                            Composite oldType = (Composite)existingType;
                            Composite newType = (Composite)currentType;
                            if (newType.getNumDefinedComponents() > oldType.getNumDefinedComponents())
                                this.replaceDataType(oldType, newType);
                        }
                    }
                } catch (Throwable th) {
                    main_gdt.endTransaction(transaction_id, false); // Cancel transaction.
                    throw new RuntimeException("An error occurred while applying the data types.", th);
                }
                main_gdt.endTransaction(transaction_id, true);
                
                typeOutput.setText("Applied Successfully");
                this.setApplyEnabled(false);
            }
            
        private void replaceDataType(DataType existing, DataType replacement) throws Exception {
            // main_gdt.addDataType(currentType, DataTypeConflictHandler.REPLACE_HANDLER);
            main_gdt.replaceDataType(existing, replacement, true);
            
            // Doesn't seem to work but whatever.
            String conflictPath = replacement.getDataTypePath().getPath() + ".conflict";
            DataType conflictType = main_gdt.getDataType(conflictPath);
            if (conflictType != null)
                main_gdt.remove(conflictType, TaskMonitor.DUMMY);
        }
        
        private String evaluateMacros(String input, ParsedCode code) {
            // Yeah this is slow, but what else am I gonna do, write a full C parse just so I resolve idents with a hashmap for an operation which runs only once?
            for (ParsedMacro macro : code.Macros.values()) {
                if (macro.hasDefinition() && input.contains(macro.Name)) {
                    input = input.replaceAll("([^a-zA-Z_])" + macro.Name + "([^a-zA-Z0-9_])", "$1" + macro.Definition + "$2");
                }
            }
            return input;
        }
            
        private void parseTypes(PrintWriter writer, List<DataTypeDefinition> dataTypeDefs, ParsedCode code) {
            boolean canFailNextTime = false;
            this.parsedTypes.clear();
    
            int errCount = 0;
            var parser = new CParser(main_gdt);
            int lastTryLaterCount = Integer.MAX_VALUE;
            List<DataTypeDefinition> tryAgainLater = new ArrayList<>();
            Set<String> seenDefinedTypes = new HashSet<>();
            Map<String, Set<String>> reliantTypes = new HashMap<>();
            do {
                for (DataTypeDefinition typeDef : dataTypeDefs) {
                    String typeDefStr = evaluateMacros(typeDef.getContents(), code);
    
                    DataType type;
                    try {
                        type = parser.parse(typeDefStr);
                        
                        if (!areAllRequiredTypesDefined(type, type, seenDefinedTypes))
                            throw new ParseException("The type '" + type.getName() + "' cannot be added yet because it relies on another type which hasn't been defined yet. (Should retry)");
                        
                        this.parsedTypes.add(type);
                        
                        boolean shouldAdd = true;
                        DataType addedType = getUnderlyingType(type, false);
                        if (addedType instanceof Composite)
                            shouldAdd = ((Composite) addedType).getNumDefinedComponents() > 0;
                        
                        if (addedType != type && !shouldAdd)
                            reliantTypes.computeIfAbsent(addedType.getName(), key -> new HashSet<>()).add(type.getName());
                        
                        if (shouldAdd) {
                            seenDefinedTypes.add(type.getName());
                            Set<String> otherTypes = reliantTypes.remove(type.getName());
                            if (otherTypes != null)
                                seenDefinedTypes.addAll(otherTypes);
                        }
                        if (writer != null)
                            writer.append(typeDefStr + "\n");
                    } catch (ParseException e) {
                        String error = e.toString();
    
                        if ((error.contains("Encountered") || error.contains("Undefined data") || error.contains(" (Should retry)")) && !canFailNextTime) {
                            tryAgainLater.add(typeDef);
                            continue;
                        }
    
                            /*typeOutput.setText("At Line #" + chunk.Line + (chunk.Source != null ? " in " + chunk.Source : "") + ",\n"
                                    + chunk.Contents + "\n" + error.replaceAll("at line ([\\d]+), column", "at column"));
                            this.setApplyEnabled(false);
                            return;*/
                        errCount++;
                        boolean shouldPrintContents = !error.contains("Undefined data");
    
                        println("ERROR! At Line #" + typeDef.Line + (typeDef.Source != null ? " in " + typeDef.Source : "") + ",\n"
                                + (shouldPrintContents ? typeDefStr + "\n" : "")
                                + error.replaceAll("at line ([\\d]+), column", "at column"));
                    } catch (Throwable th) {
                        println("Failed to write contents for " + typeDef);
                    }
                }
    
                boolean canFailThisTime = canFailNextTime;
                canFailNextTime = (lastTryLaterCount == tryAgainLater.size());
                lastTryLaterCount = tryAgainLater.size();
                dataTypeDefs.clear();
                dataTypeDefs.addAll(tryAgainLater);
                tryAgainLater.clear();
    
                if (canFailThisTime && canFailNextTime)
                    dataTypeDefs.clear();
            } while (dataTypeDefs.size() > 0);
    
            // Finish, setup output.
            StringBuilder builder = new StringBuilder("Errors: ").append(errCount).append("\n");
            builder.append("Tested Flags:\n");
    
            List<String> sortedSeenFlags = new ArrayList<>(code.MacroFlags);
            Collections.sort(sortedSeenFlags);
    
            for (String flag : sortedSeenFlags)
                if (!flag.endsWith("_H"))
                    builder.append(" - ").append(flag).append("\n");
            builder.append("\n");
    
            builder.append("Active Flags:\n");
            for (ParsedMacro macro : code.Macros.values())
                if (!macro.hasDefinition() && !macro.Name.endsWith("_H"))
                    builder.append(" - ").append(macro.Name).append("\n");
            builder.append("\n");
    
            for (DataType dataType : this.parsedTypes)
                builder.append(dataType.toString()).append("\n");
    
            this.typeOutput.setText(builder.toString());
            this.setApplyEnabled(true);
        }
        
        public DataType getUnderlyingType(DataType type, boolean allowTypedef) {
            while ((!allowTypedef && type instanceof TypeDef) || type instanceof Pointer || type instanceof Array) {
                if (!allowTypedef && type instanceof TypeDef)
                    type = ((TypeDef) type).getBaseDataType();
                if (type instanceof Pointer)
                    type = ((Pointer) type).getDataType();
                if (type instanceof Array)
                    type = ((Array) type).getDataType();
            }
            
            return type;
        }
        
        public boolean areAllRequiredTypesDefined(DataType targetType, DataType type, Set<String> definedTypes) throws ParseException {
            boolean isFirstLayer = (targetType == type);
            type = getUnderlyingType(type, false);
            
            if (type instanceof VoidDataType || type instanceof AbstractIntegerDataType || type instanceof BuiltInDataType
                || type instanceof AbstractFloatDataType || type instanceof AbstractStringDataType || type instanceof Undefined
                || (!isFirstLayer && type instanceof FunctionDefinition))
                return true; // Primitive types should already be defined.
            
            if (!isFirstLayer && targetType.getName().equals(type.getName()))
                return true;
            
            if (definedTypes.contains(type.getName()))
                return true; // This type has already been defined.
            
            if (!isFirstLayer) // Don't go further, since only the first layer can return true when the type is not seen in definedTypes.
                throw new ParseException("The type '" + targetType.getName() + "' requires '" + type.getName() + "', which has not been defined yet. (Should retry) (" + type.getClass() + ")");
            
            if (type instanceof FunctionDefinition) {
                FunctionDefinition funcDef = (FunctionDefinition) type;
                if (!areAllRequiredTypesDefined(targetType, funcDef.getReturnType(), definedTypes))
                    return false;
                
                for (ParameterDefinition parameter : funcDef.getArguments())
                    if (!areAllRequiredTypesDefined(targetType, parameter.getDataType(), definedTypes))
                        return false;
            }
            
            if (type instanceof Composite) {
                DataTypeComponent[] components = ((Composite) type).getDefinedComponents();
                for (int i = 0; i < components.length; i++) {
                    DataTypeComponent component = components[i];
                    DataType comType = component.getDataType();
                    String comTypeName = comType.getName();
                    if (comTypeName.startsWith("_struct") || comTypeName.startsWith("_enum") || comTypeName.startsWith("_union"))
                        continue; // Inline definitions can be skipped.
                    
                    if (!comTypeName.equals(type.getName()) && !comTypeName.equals(targetType.getName()) && !areAllRequiredTypesDefined(targetType, comType, definedTypes))
                        return false;
                }
            }
            
            if (type instanceof TypeDef) {
                DataType srcType = ((TypeDef) type).getBaseDataType();
                
                if (!areAllRequiredTypesDefined(targetType, srcType, definedTypes))
                    throw new ParseException("The type '" + targetType.getName() + "' is created from '" + srcType.getName() + "', which has not been defined yet. (Should retry) (" + srcType.getClass() + ")");
            }
            
            // Only valid if the one tested is the one getting defined.
            return true;
        }
    
        private boolean isWhiteSpace(char test) {
            return test == ' ' || test == '\t';
        }
    
        private boolean isWhiteSpaceOrNewLine(char test) {
            return isWhiteSpace(test) || test == '\r' || test == '\n';
        }
    
        private ParsedCode parseCode(String code, String source) {
            return parseCode(Arrays.asList(code.split("\n")), source);
        }
    
        private ParsedCode parseCode(List<String> codeLines, String source) {
            ParsedCode result = new ParsedCode();
    
            StringBuilder macroBuilder = new StringBuilder();
            ParsedMacro currentMacro = null; // If this isn't null, a macro is currently being parsed.
    
            int blockNestLevel = 0;
            int parenNestLevel = 0;
            int blockStartNestLevel = 0;
            boolean isReadingString = false;
            boolean isStringSingleQuote = false;
            boolean isReadingMultilineComment = false;
            boolean parsingDataTypeBlock = false;
            boolean parsingFunctionDef = false;
            StringBuilder currentLineBuilder = new StringBuilder();
            StringBuilder blockBuilder = new StringBuilder();
            List<String> ifStack = new ArrayList<>(); // Pulling a Vaquxine here. I don't think it's worth the effort of doing it better.
            StringReader lineReader = new StringReader(null);
            String lastTrimmedLine = "";
            for (int lineId = 1; lineId <= codeLines.size(); lineId++) {
                String line = codeLines.get(lineId - 1);
    
                currentLineBuilder.setLength(0);
                boolean seenAnyNonWhitespaceChars = false;
                boolean shouldSkipLine = false;
                boolean lineHasPreprocessorDirective = false;
                int blockNestLevelBeforeLine = blockNestLevel;
                int parenLevelBeforeLine = parenNestLevel;
                boolean isEscape = false;
                int parenthesisOpenOnLine = 0;
                int parenthesisCloseOnLine = 0;
                for (int i = 0; i < line.length(); i++) {
                    char temp = line.charAt(i);
                    char nextChar = (i + 1 < line.length()) ? line.charAt(i + 1) : '\0';
    
                    if (isReadingString) {
                        if (!isEscape && temp == (isStringSingleQuote ? '\'' : '\"'))
                            isReadingString = false;
                        isEscape = (temp == '\\' && !isEscape);
                    } else if (isReadingMultilineComment) {
                        if (temp == '*' && nextChar == '/') {
                            isReadingMultilineComment = false;
                            i++;
                            continue; // Prevent writing it.
                        }
                    } else if (temp == '/' && nextChar == '*') {
                        isReadingMultilineComment = true;
                    } else if (temp == '\"') {
                        isReadingString = true;
                        isStringSingleQuote = false;
                    } else if (temp == '\'') {
                        isReadingString = true;
                        isStringSingleQuote = true;
                    } else if (temp == '(') {
                        parenNestLevel++;
                        parenthesisOpenOnLine++;
                    } else if (temp == ')') {
                        parenNestLevel--;
                        parenthesisCloseOnLine++;
                    } else if (temp == '{') {
                        blockNestLevel++;
                    } else if (temp == '}') {
                        blockNestLevel--;
                        if (blockNestLevel < 0)
                            throw new RuntimeException("Too many bracket closures for\n" + blockBuilder.toString());
                    } else if (temp == '/' && nextChar == '/') {
                        break; // Found comment, so stop looking on this line.
                    } else if (temp == '#' && !seenAnyNonWhitespaceChars) {
                        lineHasPreprocessorDirective = true;
                        lineReader.setNewInput(line);
                        lineReader.setIndex(i + 1);
    
                        String instruction = lineReader.readUntilWhitespace();
    
                        if (instruction.equals("if")) {
                            lineReader.skipWhitespace(true);
                            String condition = lineReader.readUntilWhitespace();
    
                            if (condition.equalsIgnoreCase("true") || condition.equals("1")) {
                                ifStack.add("true|true"); // shouldSkipLine|shouldIncludeContents
                                shouldSkipLine = true;
                            } else if (condition.equalsIgnoreCase("false") || condition.equals("0")) {
                                ifStack.add("true|false"); // shouldSkipLine|shouldIncludeContents
                                shouldSkipLine = true;
                            } else {
                                ifStack.add("false|true"); // shouldSkipLine|shouldIncludeContents
                            }
                        } else if (instruction.equals("ifdef")) {
                            lineReader.skipWhitespace(true);
                            String flagName = lineReader.readUntilWhitespace();
    
                            result.MacroFlags.add(flagName);
                            shouldSkipLine = true;
                            ifStack.add("true|" + (FLAGS_BOTH.contains(flagName) ? "*true" : "" + result.isDefined(flagName)));
                        } else if (instruction.equals("ifndef")) {
                            lineReader.skipWhitespace(true);
                            String flagName = lineReader.readUntilWhitespace();
    
                            result.MacroFlags.add(flagName);
                            shouldSkipLine = true;
                            ifStack.add("true|" + (FLAGS_BOTH.contains(flagName) ? "*true" : "" + !result.isDefined(flagName)));
                        } else if (instruction.equals("else")) {
                            if (ifStack.size() == 0)
                                throw new RuntimeException("Cannot do else at line " + lineId + ", column " + i + (source != null ? " in " + source : "") + ".");
    
                            String currentIf = ifStack.get(ifStack.size() - 1);
                            boolean shouldSkipInclude = currentIf.startsWith("true");
                            boolean shouldIncludeContent = currentIf.endsWith("true");
                            boolean doesNotChange = currentIf.endsWith("*" + shouldIncludeContent);
                            
                            if (shouldSkipInclude) { // Flip whether or not content should be shown.
                                boolean shouldIncludeContentAfterFlip = doesNotChange ? shouldIncludeContent : !shouldIncludeContent;
                                ifStack.set(ifStack.size() - 1, "true|" + (doesNotChange ? "*" : "") + shouldIncludeContentAfterFlip);
                                shouldSkipLine = true;
                            }
                        } else if (instruction.equals("endif")) {
                            if (ifStack.size() == 0)
                                throw new RuntimeException("Cannot do endif at line " + lineId + ", column " + i + (source != null ? " in " + source : "") + ".");
    
                            String poppedIf = ifStack.remove(ifStack.size() - 1);
                            shouldSkipLine = poppedIf.startsWith("true");
                        }
    
                        if (shouldSkipLine)
                            i = lineReader.getIndex();
                    }
    
                    if (!isReadingMultilineComment)
                        currentLineBuilder.append(temp);
    
                    if (!seenAnyNonWhitespaceChars && !isWhiteSpace(temp))
                        seenAnyNonWhitespaceChars = true;
                }
    
                if (ifStack.size() > 0) {
                    boolean shouldIncludeContent = true;
                    for (int i = 0; i < ifStack.size() && shouldIncludeContent; i++)
                        if (!ifStack.get(i).endsWith("true"))
                            shouldIncludeContent = false;
    
                    if (!shouldIncludeContent)
                        continue;
                }
    
                if (shouldSkipLine)
                    continue;
    
                // Get line.
                line = currentLineBuilder.toString();
                String trimmedLine = line.trim();
                currentLineBuilder.setLength(0);
                
                String lastLine = lastTrimmedLine;
                lastTrimmedLine = trimmedLine;
    
                // Macro Builder. (Multi-line)
                if (currentMacro != null) {        
                
                    // If the line has a preprocessor directive, end the existing macro, but handle the directive.
                    if (!lineHasPreprocessorDirective) {
                        if (trimmedLine.endsWith("\\")) { // Continues further.
                            macroBuilder.append(trimmedLine.substring(0, trimmedLine.length() - 1).trim()).append("\n");
                            continue; // Don't end the macro.
                        } else {
                            macroBuilder.append(trimmedLine);
                        }
                    }
                    
                    currentMacro.Definition = macroBuilder.toString();
                    result.addMacro(currentMacro);
                    
                    macroBuilder.setLength(0);
                    currentMacro = null;
                        
                    if (!lineHasPreprocessorDirective)
                        continue; // Skip, unless there's a preprocessor directive.
                }
                
                // Allow skipping empty lines. Should be done after the macro runs though, since this can cause macros to include lines they weren't meant to include.
                if (trimmedLine.isEmpty())
                    continue;
    
                // Preprocessor.
                if (lineHasPreprocessorDirective) {
                    lineReader.setNewInput(trimmedLine);
                    lineReader.setIndex(trimmedLine.indexOf('#') + 1);
    
                    String instruction = lineReader.readUntilWhitespace();
    
                    if (instruction.equals("define")) {
                        lineReader.skipWhitespace(true);
    
                        String macroName = lineReader.readUntilWhitespace();
                        lineReader.skipWhitespace();
    
                        if (lineReader.hasMore()) {
                            String macroValue = lineReader.readUntilEndOfLine();
    
                            if (macroValue.endsWith("\\")) { // Continues further.
                                macroBuilder.append(macroValue.substring(0, macroValue.length() - 1).trim()).append("\n");
                                currentMacro = new ParsedMacro(source, lineId, macroName, null);
                            } else {
                                result.addMacro(new ParsedMacro(source, lineId, macroName, macroValue));
                            }
                        } else { // Empty macro.
                            result.addMacro(new ParsedMacro(source, lineId, macroName, null));
                        }
                    }
                    
                    continue;
                }
    
                boolean lineProbablyDefinesDataType = (parenNestLevel == 0 && parenLevelBeforeLine == 0) &&
                        (trimmedLine.startsWith("enum") || trimmedLine.startsWith("struct") || trimmedLine.startsWith("union") || trimmedLine.startsWith("typedef"));
    
                boolean probablyFunctionImplSignature = (blockNestLevelBeforeLine == 0) && !trimmedLine.endsWith(";") && !trimmedLine.contains("=")
                        && (parenthesisOpenOnLine >= parenthesisCloseOnLine && parenthesisOpenOnLine > 0);
    
                // Parse function signature. (NOTE: Only parses functions with bodies.)
                if (!parsingDataTypeBlock && (parsingFunctionDef || probablyFunctionImplSignature)) {
                    if (!parsingFunctionDef) {
                        parsingFunctionDef = true;
                        if (trimmedLine.startsWith("(") && blockBuilder.length() == 0)
                            blockBuilder.append(lastLine).append("\n");
                    }
    
                    String addLine = trimmedLine;
                    if (parenNestLevel == 0 && parenthesisCloseOnLine > 0)
                        addLine = addLine.substring(0, addLine.lastIndexOf(')') + 1);
    
                    if (blockBuilder.length() > 0)
                        blockBuilder.append("\n");
                    blockBuilder.append(addLine);
    
                    if (parenNestLevel == 0) { // Finished
                        if (!trimmedLine.endsWith(";") && !trimmedLine.contains("=")) { // Test now that it's not a declaration.
                            String funcBlock = blockBuilder.toString();
                            if (!funcBlock.startsWith("inline")) // Inline functions are skipped.
                                result.addFunctionSignature(new FunctionImplSignature(source, lineId, funcBlock));
                        }
    
                        // Cleanup.
                        blockBuilder.setLength(0);
                        parsingFunctionDef = false;
                    }
                    continue;
                }
    
    
                // Parsing datatype.
                if (lineProbablyDefinesDataType || parsingDataTypeBlock) {
                    if (!parsingDataTypeBlock) {
                        blockStartNestLevel = blockNestLevelBeforeLine;
                        parsingDataTypeBlock = true;
                    }
    
                    blockBuilder.append(line).append("\n");
    
                    // Reached the end of the definition.
                    if (trimmedLine.endsWith(";") && blockNestLevel <= blockStartNestLevel) {
                        String str = blockBuilder.toString().replaceAll("\\((\\s*)MR_VOID(\\s*)\\)", "()"); // Replaces void arguments with empty arguments, since ghidra doesn't understand void parameters.
                        result.addDataTypeDefinition(new DataTypeDefinition(source, lineId, str));
    
                        // Cleanup.
                        blockBuilder.setLength(0);
                        parsingDataTypeBlock = false;
                        blockStartNestLevel = 0;
                    }
                    continue;
                }
                
                if (trimmedLine.startsWith("extern") && !parsingDataTypeBlock && !parsingFunctionDef && !probablyFunctionImplSignature && parenthesisOpenOnLine == 0) {
                    String lineWithoutExtern = trimmedLine.substring("extern".length()).trim();
                    
                    if (lineWithoutExtern.contains(";")) {
                        int index = lineWithoutExtern.indexOf(";");
                        int lastIndex = lineWithoutExtern.lastIndexOf(";");
                        if (index != lastIndex)
                            throw new RuntimeException("Cannot parse extern, line: '" + trimmedLine + "' has two semicolons. (Source: " + source + ", Line: " + lineId + ")");
                        
                        String removedSemicolon = lineWithoutExtern.substring(0, lastIndex).trim();
                        result.addExtern(new ExternDefinition(source, lineId, removedSemicolon));
                    } else if (lineWithoutExtern.contains("=")) {
                        result.addExtern(new ExternDefinition(source, lineId, lineWithoutExtern.split("=")[0].trim()));
                    } else {
                        throw new RuntimeException("Could not parse extern, line: '" + trimmedLine + "', didn't seem to actually define anything. (Source: " + source + ", Line: " + lineId + ")");
                    }
                    continue;
                }
            }
    
            return result;
        }
    
        private class ParsedCode {
            public List<DataChunk> AllChunks = new ArrayList<>();
            public Map<String, ParsedMacro> Macros = new HashMap<>();
            public List<DataTypeDefinition> DataTypeDefinitions = new ArrayList<>();
            public List<ExternDefinition> Externs = new ArrayList<>();
            public List<FunctionImplSignature> FunctionSignatures = new ArrayList<>();
            public Set<String> MacroFlags = new HashSet<>();
            
            public boolean isDefined(String macro) {
                return macro != null && (IFDEF_FLAGS.contains(macro) || this.Macros.containsKey(macro));
            }
    
            public void addMacro(ParsedMacro macro) {
                AllChunks.add(macro);
    
                ParsedMacro existingMacro = this.Macros.get(macro.Name);
                if (existingMacro != null) {
                    if (!Objects.equals(macro.Definition, existingMacro.Definition)) {
                        println("The macro '" + macro.Name + "' is defined twice. ("
                                + existingMacro.getDebugString() + "), (" + macro.getDebugString() + ")");
                        /*throw new RuntimeException("The macro '" + macro.Name + "' is defined twice. ("
                                + existingMacro.getDebugString() + "), (" + macro.getDebugString() + ")");*/
                    }
                } else {
                    this.Macros.put(macro.Name, macro);
                }
            }
    
            public void addDataTypeDefinition(DataTypeDefinition definition) {
                this.AllChunks.add(definition);
                this.DataTypeDefinitions.add(definition);
            }
    
            public void addFunctionSignature(FunctionImplSignature signature) {
                this.AllChunks.add(signature);
                this.FunctionSignatures.add(signature);
            }
            
            public void addExtern(ExternDefinition extern) {
                this.AllChunks.add(extern);
                this.Externs.add(extern);
            }
    
            public void addChunks(ParsedCode otherCode) {
                otherCode.AllChunks.forEach(this::addChunk);
            }
    
            public void addChunk(DataChunk chunk) {
                if (chunk instanceof ParsedMacro) {
                    this.addMacro((ParsedMacro) chunk);
                } else if (chunk instanceof DataTypeDefinition) {
                    this.addDataTypeDefinition((DataTypeDefinition) chunk);
                } else if (chunk instanceof FunctionImplSignature) {
                    this.addFunctionSignature((FunctionImplSignature) chunk);
                } else if (chunk instanceof ExternDefinition) {
                    this.addExtern((ExternDefinition) chunk);
                } else {
                    throw new RuntimeException("Don't know how to add the chunk '" + chunk.getClass().getSimpleName() + "'.");
                }
            }
    
        }
    
        @SuppressWarnings("InnerClassMayBeStatic")
        private abstract class DataChunk {
            public String Source;
            public int Line;
    
            public DataChunk(String source, int line) {
                this.Source = source;
                this.Line = line;
            }
    
            public abstract String getContents();
    
            public String getDebugString() {
                return "'" + this.getContents() + "'@" + this.Source + ":" + this.Line;
            }
        }
    
        private class DataTypeDefinition extends DataChunk {
            private final String definitionBlock;
    
            public DataTypeDefinition(String source, int line, String definitionBlock) {
                super(source, line);
                this.definitionBlock = definitionBlock;
            }
    
            @Override
            public String getContents() {
                return this.definitionBlock;
            }
        }
        
        private class ExternDefinition extends DataChunk {
            public String definitionBlock;
    
            public ExternDefinition(String source, int line, String definitionBlock) {
                super(source, line);
                this.definitionBlock = definitionBlock;
            }
    
            @Override
            public String getContents() {
                return "extern " + this.definitionBlock + ";";
            }
        }
    
        private class FunctionImplSignature extends DataChunk {
            private String signature;
    
            public FunctionImplSignature(String source, int line, String signature) {
                super(source, line);
                this.signature = signature
                    .replace("\n", "\n\t")
                    .replaceFirst("\\((\\s*)MR_VOID(\\s*)\\)", "()") // Avoids any confusion for what MR_VOID (not ptr) in the arguments means.
                    .replace("STATIC", "") // I'm not sure why this is even here, this is a macro that gets replaced with nothing.
                    .replace("static", "") // I'm not sure why this is even here, this is a macro that gets replaced with nothing.
                    .replace("struct ", "") // It doesn't parse types prefixed with 'struct ', despite this being valid C.
                    .replace("enum ", "") // It doesn't parse types prefixed with 'enum ', despite this being valid C.
                    .replaceAll("\\s+", " "); // Somehow, it doesn't even support tabs for whitespace.
                    
                int ptrOnFunctionNameIndex = this.signature.indexOf(" *");
                int parenthesisIndex = this.signature.indexOf("(");
                
                // It doesn't parse functions which have the pointer asterisk on its name, despite this being valid C.
                if (ptrOnFunctionNameIndex != -1 && ptrOnFunctionNameIndex < parenthesisIndex) {
                    this.signature = this.signature.substring(0, ptrOnFunctionNameIndex)
                            + "* " + this.signature.substring(ptrOnFunctionNameIndex + 2);
                }
                
                // PTRFUNC doesn't seem to work for some reason. It's weird because I can manually apply it, the ghidra parser just doesn't like it. So, we'll replace it with MR_VOID* as a placeholder.
                this.signature = this.signature.replaceAll("PTRFUNC(\\s+[a-zA-Z])", "MR_VOID*$1");
                
                // Change array declaration to be on the type, not the var name, since the ghidra parser doesn't understand that.
                this.signature = this.signature.replaceAll("([a-zA-Z0-9_]+)\\s+([a-zA-Z0-9_]+)\\[]", "$1[] $2");
            }
    
            @Override
            public String getContents() {
                return this.signature;
            }
        }
    
        private class ParsedMacro extends DataChunk {
            public String Name;
            public String Definition;
    
            public ParsedMacro(String source, int line, String name, String value) {
                super(source, line);
                this.Name = name;
                this.Definition = value;
            }
    
            @Override
            public String getContents() {
                return "#define " + this.Name +
                        (hasDefinition() ? " " + this.Definition.replace("\n", " \\" + "\n\t") : "");
            }
    
            public boolean hasDefinition() {
                return this.Definition != null && this.Definition.length() > 0;
            }
        }
    
        private class StringReader {
            private final Stack<Integer> jumpStack = new Stack<>();
            private final StringBuilder cachedTempBuilder = new StringBuilder();
            private String input;
            private int index;
    
            public StringReader(String input) {
                this.input = input;
            }
    
            public void setIndex(int index) {
                this.index = index;
            }
    
            public int getIndex() {
                return this.index;
            }
    
            public void skipWhitespace() {
                skipWhitespace(false);
            }
    
            public void skipWhitespace(boolean requireWhiteSpace) {
                if (requireWhiteSpace && !isWhiteSpace(peekChar()))
                    throw new RuntimeException("Expected whitespace padding, but got '" + peekChar() + "' instead.");
                while (hasMore() && isWhiteSpace(peekChar()))
                    this.index++;
            }
    
            public boolean hasMore() {
                return getRemaining() > 0;
            }
    
            public int getRemaining() {
                return Math.min(this.input.length(), Math.max(0, this.input.length() - this.index));
            }
    
            public String readUntilWhitespace() {
                while (hasMore() && !isWhiteSpace(peekChar()))
                    this.cachedTempBuilder.append(readChar());
    
                String result = this.cachedTempBuilder.toString();
                this.cachedTempBuilder.setLength(0);
                return result;
            }
    
            public String readUntilEndOfLine() {
                while (hasMore() && peekChar() != '\n')
                    this.cachedTempBuilder.append(readChar());
    
                if (hasMore())
                    this.index++; // Skip the '\n'.
    
                String result = this.cachedTempBuilder.toString();
                this.cachedTempBuilder.setLength(0);
                return result;
            }
    
            public char peekChar() {
                if (this.index < 0 || this.index >= this.input.length())
                    throw new StringIndexOutOfBoundsException("The index '" + this.index + "' is outside the range of the string.");
                return this.input.charAt(this.index);
            }
    
            public char readChar() {
                if (this.index < 0 || this.index >= this.input.length())
                    throw new StringIndexOutOfBoundsException("The index '" + this.index + "' is outside the range of the string.");
                return this.input.charAt(this.index++);
            }
    
            public void jumpTemp(int jumpIndex) {
                this.jumpStack.push(this.index);
                this.index = jumpIndex;
            }
    
            public void jumpReturn() {
                if (this.jumpStack.isEmpty())
                    throw new RuntimeException("Cannot pop empty jump stack!");
                this.index = this.jumpStack.pop();
            }
    
            public void setNewInput(String newString) {
                this.input = newString;
                this.index = 0;
                this.cachedTempBuilder.setLength(0);
                this.jumpStack.clear();
            }
        }
    }
}
