# Ghidra Scripts
Custom scripts to make analyzing malware easier in Ghidra
## Installation
Add these scripts to your Ghidra scripts directory:
1. Open any file in Ghidra for analysis
2. Select the Window / Script Manager menu
3. Click the "Script Directories" icon in the upper right toolbar
4. Add the directory where your scripts are located via the green plus sign
## Clear_All_Instruction_Colors.py
Removes all highlight colors from current program.  Applied highlighting colors are saved with the ghidra file.
This script can be used to remove the colors prior to exporting and sharing the ghidra database so that the highlight colors don't clash with different color schemes used by coworkers. See script header for more usage details.
## Highlight_Target_Instructions.py
Script to search all instructions in current program looking for target instructions of interest.  When found,
a defined highlighting color will be applied to make it easy to identify target instructions.  Target instructions are things like call instructions, potential crypto operations, pointer instructions, etc.  Highlighting instructions of interest decrease the chance of missing important instructions when skimming malware code. See script header for more usage details.

**Default color choices are made to work with the AGDC_codeBrowser_##.tool.  They can be changed to fit any coloring schema by modifying the defined color constants at the top of the script**
## Minimize_Automatic_Function_Comments.py
Adds a single space as a repeatable comment to all functions within the current program.  By default, Ghidra adds a function prototype as a repeatable comment to all functions.  These comments are very long which will force the code block to expand it its maximum size within the graph view.  These default comments do not add any real value and decreases the amount of code that can be seen in the graph view.

Currently, there is no way to turn this option off.  A work around is to replace the repeatable comment with a single space so that you don't see any comment by default, and the code block is not expanded out to 
it's maximum size because of the long function prototype comment. See script header for more usage details.
## Utils.py
A number of commonly used convenience functions to aid in rapid scripting, e.g. Get_Operand_As_Immediate_Value, Get_Next_Target_Instruction, Get_Bytes, etc.  Need to copy them into target script to run, Ghidra won't let you import the entire module into a script and use the functions that way. See script header for more usage details.
## Label_Dynamically_Resolved_Iat_Entries.py
Script to aid in reverse engineering files that dynamically resolve imports. Script will search program for all dynamically resolved imports and label them with the appropriate API name pulled from a provided labeled IAT dump file.  Only resolved imports stored in global variables will be identified. This script will not label every resolved global variable, but only those that are used inside a call instruction.

The labeled IAT dump file must be generated by an associated program, "Dump_Labeled_Iat_Memory.exe". This program is located in another repo on this github site called "Misc Malware Anaysis Tools".  See script header for more usage details.

