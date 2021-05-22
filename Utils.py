from __main__ import *

'''
Utility module of common helper functions used
in building Ghidra scripts

Contained function prototypes below:
    Get_Bytes_List(targetEa, nLen)
    Get_Bytes_String(targetEa, nLen)
    Get_Ascii_String(targetEa)
    Get_Call_Xrefs_To(targetEa)
    Get_Prev_Target_Instruction(curInstr, mnem, N, MAX_INSTRUCTIONS = 9999)
    Get_Next_Target_Instruction(curInstr, mnem, N, MAX_INSTRUCTIONS = 9999)
    Get_Operand_As_Address(targetInstr, operandIndex)
    Get_Operand_As_Immediate_Value(targetInstr, operandIndex)
    Get_Operand_As_String(targetInstr, operandIndex)

'''

def Get_Bytes_List(targetEa, nLen):
    '''
    gets the bytes from memory, treating as unsigned bytes
    ghidra treats read bytes as signed which is not what
    you normally want when reading memory, e.g. if you call
    getBytes on a byte 0xfe, you won't get 0xfe, you'll get -2
    this may not be an issue depending on what operation you
    are performing, or it may, e.g. reading a byte that is
    displayed as a negative value will fail when compared to
    the two's complement hex (-2 != 0xfe).  If you're using
    the byte to patch the program, it may work ok.

    returns result as a list
    '''

    signedList = list(getBytes(targetEa, nLen))
    unsignedList = []
    for curByte in signedList:
        if curByte < 0:
            uByte = (0xff - abs(curByte) + 1)
        else:
            uByte= curByte
        unsignedList.append(uByte)

    return unsignedList

def Get_Bytes_String(targetEa, nLen):
    '''
    gets the bytes from memory, treating as unsigned bytes
    ghidra treats read bytes as signed which is not what
    you normally want when reading memory, e.g. if you call
    getBytes on a byte 0xfe, you won't get 0xfe, you'll get -2
    this may not be an issue depending on what operation you
    are performing, or it may, e.g. reading a byte that is
    displayed as a negative value will fail when compared to
    the two's complement hex (-2 != 0xfe).  If you're using
    the byte to patch the program, it may work ok.

    returns result as a string
    '''

    signedList = list(getBytes(targetEa, nLen))
    unsignedList = []
    for curByte in signedList:
        if curByte < 0:
            uByte = (0xff - abs(curByte) + 1)
        else:
            uByte= curByte
        unsignedList.append(chr(uByte))

    return ''.join(unsignedList)


def Get_Ascii_String(targetEa):
    '''
    returns the null terminated ascii string starting
    at targetEa.  Returns a string object and does not
    include the terminating null character

    targetEa must be an address object
    '''

    result = ''
    i = 0
    while True:
        curByte = chr(getByte(targetEa.add(i)))
        if curByte == chr(0): break
        result += curByte
        i += 1

    return result

def Get_Call_Xrefs_To(targetEa):
    '''
    returns list of addresses which call the targetEa

    '''

    callEaList = []
    for ref in getReferencesTo(targetEa):
        if getInstructionAt(ref.getFromAddress()).getMnemonicString().lower() == 'call':
            callEaList.append(ref.getFromAddress())

    return callEaList

def Get_Prev_Target_Instruction(curInstr, mnem, N, MAX_INSTRUCTIONS = 9999):
    '''
    gets N'th previous target instruction from the curInstr
    function will only go back MAX_INSTRUCTIONS
    function will not search outside of current function if the
    current instruction is inside a defined function
    returns None on failure
    '''


    # get address set of current function to use in determining if prev instruction
    # is outside of current function
    try:
        funcBody = getFunctionContaining(curInstr.getAddress()).getBody()
    except:
        funcBody = None


    # get Nth prev instruction
    totalInstructionCount = 0
    targetInstructionCount = 0
    while (totalInstructionCount < MAX_INSTRUCTIONS) and (targetInstructionCount < N):
        curInstr = curInstr.getPrevious()

        if curInstr == None: break
        if funcBody != None:
            if funcBody.contains(curInstr.getAddress()) == False: break

        if curInstr.getMnemonicString().lower() == mnem.lower(): targetInstructionCount += 1

        totalInstructionCount += 1


    # return the results
    if targetInstructionCount == N:
        result = curInstr
    else:
        result = None

    return result

def Get_Next_Target_Instruction(curInstr, mnem, N, MAX_INSTRUCTIONS = 9999):
    '''
    gets N'th next target instruction from the curInstr
    function will only go forward MAX_INSTRUCTIONS
    function will not search outside of current function if the
    current instruction is inside defined function
    returns None on failure
    '''

    # get address set of current function to use in determining if prev instruction
    # is outside of current function
    try:
        funcBody = getFunctionContaining(curInstr.getAddress()).getBody()
    except:
        funcBody = None


    # get Nth next instruction
    totalInstructionCount = 0
    targetInstructionCount = 0
    while (totalInstructionCount < MAX_INSTRUCTIONS) and (targetInstructionCount < N):
        curInstr = curInstr.getNext()

        if curInstr == None: break
        if funcBody != None:
            if funcBody.contains(curInstr.getAddress()) == False: break

        if curInstr.getMnemonicString().lower() == mnem.lower(): targetInstructionCount += 1

        totalInstructionCount += 1


    # return the results
    if targetInstructionCount == N:
        result = curInstr
    else:
        result = None

    return result

def Get_Operand_As_Address(targetInstr, operandIndex):
    '''
    returns the value for the operandIndex operand of the
    target instruction treated as an address.  if the
    target operand can not be treated as an address,
    returns None.  operandIndex starts at 0

    If this is called on jumps or calls, the final
    address jumped to / called will be returned

    There are no real checks for validity and it's up to
    the author to ensure the target operand should be an address

    '''

    # error check
    if operandIndex >= targetInstr.getNumOperands():
        print('[*] Error in Get_Operand_As_Address.  operandIndex is too large at {:s}'.format(targetInstr.getAddress().toString()))
        return None
    elif targetInstr.getNumOperands() == 0:
        return None


    operand = targetInstr.getOpObjects(operandIndex)[0]
    if type(operand) == ghidra.program.model.scalar.Scalar:
        targetValue = toAddr(operand.getValue())
    elif type(operand) == ghidra.program.model.address.GenericAddress:
        targetValue = operand
    else:
        targetValue = None

    return targetValue

def Get_Operand_As_Immediate_Value(targetInstr, operandIndex):
    '''
    returns the value for the operandIndex operand of the target instruction
    if the target operand is not an immediate value, the function will attempt
    to find where the variable was previously set.  It will ONLY search within
    the current function to find where the variable was previously set.
    if operand value can not be determined, returns None
    operandIndex starts at 0
    '''

    # operand types are typically different if operand is
    # used in a call versus not a call and if there is a
    # reference or not
    OP_TYPE_IMMEDIATE = 16384
    OP_TYPE_NO_CALL_REG = 512
    OP_TYPE_NO_CALL_STACK = 4202496
    # global variables have numerous reference types
    # unsure how to differentiate the different types


    # error check
    if operandIndex >= targetInstr.getNumOperands():
        print('[*] Error in Get_Operand_As_Immediate_Value.  operandIndex is too large at {:s}'.format(targetInstr.getAddress().toString()))
        return None
    elif targetInstr.getNumOperands() == 0:
        return None


    # get address set of current function to use in determining
    # if prev instruction is outside of current function
    try:
        funcBody = getFunctionContaining(targetInstr.getAddress()).getBody()
    except:
        funcBody = None


    # find the actual operand value
    targetValue = None
    opType = targetInstr.getOperandType(operandIndex)
    # if operand is a direct number
    if opType == OP_TYPE_IMMEDIATE:
        targetValue = targetInstr.getOpObjects(operandIndex)[0].getValue()
    # else if operand is a register
    elif opType == OP_TYPE_NO_CALL_REG:
        regName = targetInstr.getOpObjects(operandIndex)[0].getName().lower()

        # search for previous location where register value was set
        curInstr = targetInstr
        while True:
            curInstr = curInstr.getPrevious()

            # check to make sure curInstr is valid
            if curInstr == None: break
            if funcBody != None:
                if funcBody.contains(curInstr.getAddress()) == False: break

            # check different variations of how register values get set
            curMnem = curInstr.getMnemonicString().lower()
            if (curMnem == 'mov') and (curInstr.getOperandType(0) == OP_TYPE_NO_CALL_REG):
                if curInstr.getOpObjects(0)[0].getName().lower() == regName:
                    if curInstr.getOperandType(1) == OP_TYPE_IMMEDIATE:
                        targetValue = curInstr.getOpObjects(1)[0].getValue()
                    elif curInstr.getOperandType(1) == OP_TYPE_NO_CALL_REG:
                        targetValue = Get_Operand_As_Immediate_Value(curInstr, 1)
                    break
            elif (curMnem == 'xor'):
                operand1 = curInstr.getOpObjects(0)[0]
                operand2 = curInstr.getOpObjects(1)[0]
                op1Type = curInstr.getOperandType(0)
                op2Type = curInstr.getOperandType(1)

                if (op1Type == OP_TYPE_NO_CALL_REG) and (op2Type == OP_TYPE_NO_CALL_REG):
                    if (operand1.getName().lower() == regName) and (operand2.getName().lower() == regName):
                        targetValue = 0
                        break
            elif (curMnem == 'pop') and (curInstr.getOperandType(0) == OP_TYPE_NO_CALL_REG):
                if curInstr.getOpObjects(0)[0].getName().lower() == regName:
                    # find previous push
                    # NOTE: assumes previous push corresponds to pop but
                    # will fail if there is a function call in-between
                    tmpCurInstr = curInstr.getPrevious()
                    while True:
                        # check to make sure tmpCurInstr is valid
                        if tmpCurInstr == None: break
                        if funcBody != None:
                            if funcBody.contains(tmpCurInstr.getAddress()) == False: break

                        if tmpCurInstr.getMnemonicString().lower() == 'push':
                            if tmpCurInstr.getOperandType(0) == OP_TYPE_IMMEDIATE:
                                targetValue = tmpCurInstr.getOpObjects(0)[0].getValue()
                            break

                    # break out of outer while loop
                    break
    # if operand is a stack variable
    elif opType == OP_TYPE_NO_CALL_STACK:
        stackOffset = targetInstr.getOperandReferences(operandIndex)[0].getStackOffset()

        # search for previous location where stack variable value was set
        curInstr = targetInstr
        while True:
            curInstr = curInstr.getPrevious()

            # check to make sure curInstr is valid
            if curInstr == None: break
            if funcBody != None:
                if funcBody.contains(curInstr.getAddress()) == False: break

            # find where stack variable was set
            curMnem = curInstr.getMnemonicString().lower()
            if (curMnem == 'mov') and (curInstr.getOperandType(0) == OP_TYPE_NO_CALL_STACK):
                if curInstr.getOperandReferences(0)[0].getStackOffset() == stackOffset:
                    if curInstr.getOperandType(1) == OP_TYPE_IMMEDIATE:
                        targetValue = curInstr.getOpObjects(1)[0].getValue()
                    break




    return targetValue

def Get_Operand_As_String(targetInstr, operandIndex):
    '''
    returns the value for the operandIndex operand of the
    target instruction treated as a string.
    operandIndex starts at 0

    If this is called on jumps or calls, the final
    address jumped to / called will be returned

    '''

    # error check
    if operandIndex >= targetInstr.getNumOperands():
        print('[*] Error in Get_Operand_As_String.  operandIndex is too large at {:s}'.format(targetInstr.getAddress().toString()))
        return None
    elif targetInstr.getNumOperands() == 0:
        return None


    operand = targetInstr.getOpObjects(operandIndex)[0]

    return operand.toString()





