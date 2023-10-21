#Imports PSX .MAP symbol files.
#@category Data
#@author 
 
f = askFile("Give me a .map file to open", "Go baby go!")

for line in file(f.absolutePath):
    if len(line) <= 1:
        continue
    
    pieces = line.split()
    if len(pieces) != 2: # Skip this line.
        print "pieces ", len(line), ", ", len(pieces), ", ", pieces[0], ", ", pieces[1]
        continue

    address = toAddr(long(pieces[0], 16))
    print "creating symbol", pieces[1], "at address", address
    createLabel(address, pieces[1], True)

