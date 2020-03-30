# Adds a short repeatable comment to all functions to hide the automatic function comment
#@author https://AGDCServices.com
#@category AGDCservices
#@keybinding
#@menupath
#@toolbar

'''
Adds a single space as a repeatable comment to all functions
within the current program.  By default, Ghidra adds a function
prototype as a repeatable comment to all functions.  These comments
are very long which will force the code block to expand it its maximum
size within the graph view.  These default comments do not add any real value
and decreases the amount of code that can be seen in the graph view.

Currently, there is no way to turn this option off.  A work around is 
to replace the repeatable comment with a single space so that you don't
see any comment by default, and the code block is not expanded out to 
it's maximum size because of the long function prototype comment.
'''

REPEATABLE_COMMENT = ghidra.program.model.listing.CodeUnit.REPEATABLE_COMMENT
listing = currentProgram.getListing()

commentCount = 0
for func in listing.getFunctions(True):
    listing.getCodeUnitAt(func.getEntryPoint()).setComment(REPEATABLE_COMMENT, ' ')
    commentCount += 1

print('Set {:d} repeatable function comments to a single space to prevent automatic function comments from being displayd'.format(commentCount))