#!/bin/bash

if [[ $# -ne 1 ]]; then
 echo "Creates a playable CD image of Frogger."
 echo "Usage: $0 <region: A|E|J>"
 echo ""
 echo "Regions:"
 echo " A - USA (NTSC-U)"
 echo " E - Europe (PAL)"
 echo " J - Japan (NTSC-J)"
 echo ""
 exit 1
fi

if [[ "$1" == "A" ]]; then
 buildFolderName="NTSC-U (USA)"
 cdExecutableFileName="SLUS_005.06"
elif [[ "$1" == "E" ]]; then
 buildFolderName="PAL (Europe)"
 cdExecutableFileName="SLES_007.04"
elif [[ "$1" == "J" ]]; then
 buildFolderName="NTSC-J (Japan)"
 cdExecutableFileName="SLPS013.99"
else
 echo "Invalid Region: $1"
 exit 1
fi

base_dir="$(dirname "${BASH_SOURCE}")"
build_path="$base_dir/build/$buildFolderName"

# Verify game has been compiled.
if [[ ! -f "$base_dir/build/frogger.exe" ]]; then
 echo "The game has not been compiled yet."
 echo "Compile the game with 'make', then try again."
 exit 1
fi

# Extract the CD image if necessary.
if [[ ! -d "$build_path/files" ]]; then
 if [[ ! -f "$build_path/original/Frogger.bin" ]]; then
  mkdir -p "$build_path/original" >&-
  echo ""
  echo "Cannot build CD image, because game files from an original Frogger PSX CD image are required first!"
  echo "Please rename your PSX Frogger CD image (iso or bin/cue) to 'Frogger.bin', and place it in:"
  echo " - $build_path/original"
  echo ""
  echo "After doing so, run this script again, and the game files will automatically be extracted."
  echo "Other formats such as .mdf, .iso, etc are not supported by the 'dumpsxiso' tool and should be avoided."
  echo ""
  exit 1
 fi
 
 "$base_dir/sdk/bin/mkpsxiso/linux-x64/dumpsxiso" -x "$build_path/files" -s "$build_path/DiscTemplate.xml" "$build_path/original/Frogger.bin"
 [[ $? -ne 0 ]] && exit 1
fi

# Move game executable.
rm -f "$base_dir/build/frogger.sym" >&-
rm -f "$build_path/files/$cdExecutableFileName" >&-
rm -f "$build_path/files/frogger.map" >&-
rm -f "$build_path/files/frogger.sym" >&-
cp -f "$base_dir/build/frogger.exe" "$build_path/files/$cdExecutableFileName" >&-
cp -f "$base_dir/build/frogger.map" "$build_path/files/" >&-

# Create .bin/.cue CD image.
rm -f "$build_path/Frogger.bin" >&-
rm -f "$build_path/Frogger.cue" >&-
"$base_dir/sdk/bin/mkpsxiso/linux-x64/mkpsxiso" --output "$build_path/Frogger.bin" --cuefile "$build_path/Frogger.cue" "$build_path/DiscTemplate.xml"
