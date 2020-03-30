# Clears all colors applied to instructions in program
#@author https://AGDCServices.com
#@category AGDCservices
#@keybinding
#@menupath
#@toolbar

'''
Removes all highlight colors from current program.
Applied highlighting colors are saved with the ghidra file.
This script can be used to remove the colors prior to exporting
and sharing the ghidra database so that the highlight colors
don't clash with different color schemes used by coworkers
'''

instructions = currentProgram.getListing().getInstructions(True)
for curInstr in instructions:
    clearBackgroundColor(curInstr.getAddress())
