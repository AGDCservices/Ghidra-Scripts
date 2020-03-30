# Highlights target instructions using custom colors for easy identification
#@author https://AGDCServices.com
#@category AGDCservices
#@keybinding
#@menupath
#@toolbar

'''
Script will search all instructions in current program
looking for target instructions of interest.  When found,
a defined highlighting color will be applied to make it
easy to identify target instructions.

default color choices are made to work with the 
AGDC_codeBrowser_14.tool.  They can be changed to fit any
coloring schema by modifying the defined color constants
at the top of the program
'''

from java.awt import Color


# define RGB colors for target instructions

# color_default sets non-target instructions colors
# needed to account for bug in graph view
COLOR_DEFAULT = Color(255,255,255) # white
COLOR_CALL = Color(255, 220, 220) #light red
COLOR_POINTER = Color(200, 240, 255) # blue
COLOR_CRYPTO = Color(245, 205, 255) # violet
COLOR_STRING_OPERATION = Color(180,230,170) # green

#
# additional unused colors
#
# Color(255,255,180) #yellow
# Color(220,255,200) #very light green
# Color(255,200,100) #orange 
# Color(220, 220, 220) #light grey
# Color(195, 195, 195) # dark grey



REG_TYPE = 512


# loop through all program instructions searching
# for target instructions.  when found, apply defined
# color
instructions = currentProgram.getListing().getInstructions(True)
for curInstr in instructions:

    bIsTargetInstruction = False

    curMnem = curInstr.getMnemonicString().lower()

    # color call instructions
    if curMnem == 'call':
        bIsTargetInstruction = True
        setBackgroundColor(curInstr.getAddress(), COLOR_CALL)


    # color lea instructions
    if curMnem == 'lea':
        bIsTargetInstruction = True
        setBackgroundColor(curInstr.getAddress(), COLOR_POINTER)


    #
    # color suspected crypto instructions
    #

    # xor that does not zero out the register
    if (curMnem == 'xor') and (curInstr.getOpObjects(0) != curInstr.getOpObjects(1)):
        bIsTargetInstruction = True
        setBackgroundColor(curInstr.getAddress(), COLOR_CRYPTO)


    # common RC4 instructions
    if (curMnem == 'cmp') and (curInstr.getOperandType(0) == REG_TYPE) and (curInstr.getOpObjects(1)[0].toString() == '0x100'):
        bIsTargetInstruction = True
        setBackgroundColor(curInstr.getAddress(), COLOR_CRYPTO)

    # misc math operations
    mathInstrList = ['sar', 'sal', 'shr', 'shl', 'ror', 'rol', 'idiv', 'div', 'imul', 'mul', 'not']
    if curMnem in mathInstrList:
        bIsTargetInstruction = True
        setBackgroundColor(curInstr.getAddress(), COLOR_CRYPTO)


	#
	#
	#



    # color string operations
    #  skip instructions that start with 'c' to exclude conditional moves, e.g. cmovs
    if (curMnem.startswith('c') == False) and (curMnem.endswith('x') == False) and ( ('scas' in curMnem) or ('movs' in curMnem) or ('stos' in curMnem) ):
        bIsTargetInstruction = True
        setBackgroundColor(curInstr.getAddress(), COLOR_STRING_OPERATION)




    # fixes ghidra bug in graph mode where if a color is applied to the first instruction of a code block
    # the color will also be applied to the rest of the instructions in that code block
    # by setting the color to every line that's not a target instruction to the default color,
    # target colors should be applied accurately
    # error only appears to be in graph view.  colors will be correctly applied in flat view, but incorrect in graph view
    # if you just clear the colors instead of setting all the colors to the default color,
    # the error will still occur.  In this case, it may get fixed by redrawing the graph,
    # but you will have to redraw the graph every time you come across an error
    if bIsTargetInstruction == False:
        setBackgroundColor(curInstr.getAddress(), COLOR_DEFAULT)



