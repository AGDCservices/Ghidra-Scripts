# Names unindentified functions with a nomenclature that provides a preview of included capabilities within the function
#@author https://AGDCServices.com
#@category AGDCservices
#@keybinding
#@menupath
#@toolbar

'''
This script will name all unidentified functions with a nomenclature
that provides a preview of important capabilities included within the
function and all child functions.

The script includes a list of hardcoded important API calls. The
script will locate all calls contained in the unidentifed function
and it's children functions. For any of the calls which match
the hardcoded API call list, a shorthand name will be applied to
indicate which category of important call is contained within the function.

The naming nomenclature is based on capability and does not identify
specific APIs. By keeping the syntax short and just for capability,
you can get a preview of all the important capabilities within a function
without having the name get enormous.

The naming convention is as follows:
- all funtions automatically named will start with a f_p__
- a function will only be renamed if it starts with either the
  Ghidra default function name, or this scripts default function name.
  If any other name is found, it is expected the function was either 
  manually named or identified by a library signature, and it is
  assumed those names are more accurate than the automated preview name.
- each category will be seperated by a double underscore
- within each catagory, a specific capability is identified by a
  single "preview" letter.
- if the preview letter is uppercase, it means the capability
  was found in the current function. If the preview letter is
  lowercase, it means the capability was found somewhere in a
  child function.
- the last entry of the preview name will be the function address
  This is because Ghidra allows duplicate names, but when a name is
  selected, all copies are highlighted based only on the name.
  Because you often get duplicates of the preview name, adding the 
  functions address to the end will make each name unique so you can
  easily differentiate functions with the same base preview name.

One exception to the naming convention are functions which are the
start of a thread. These functions will only have the category
TS applied and will not contain any capability preview.
Because the thread starts are almost like mini-programs, this 
identifer is used just to identify the starting functions so you 
can manually review them to determine the general capabilities    
    
The preview letters are all single characters that are typically
the first letter of the capability. The categories and preview
letters used are below. To see the specific API calls that
correspond to each capability, see the list at the top of the
function, Build_New_Func_Name()


TS = thread start (no further capability preview will be applied)

netw = networking functionality
  b = build
  c = connect
  l = listen
  s = send
  r = receive
  t = terminate
  m = modify

reg = registry functionality
  h = handle
  r = read
  w = write
  d = delete

file = file processing functionality
  h = handle
  r = read
  w = write
  d = delete
  c = copy
  m = move
  e = enumerate

proc = process manipulation functionality
  h = handle
  e = enumerate
  c = create
  t = terminate
  r = read process memory
  w = write process memory

serv = service manipulation functionality
  h = handle
  c = create
  d = delete
  s = start
  r = read
  w = write

thread = thread functionality
  c = create
  o = open
  s = suspend
  r = resume

str = string manipulation functionality
  c = compare

zc = there were no call instructions in the function

xref = number of cross references for the function

'''


import re
import collections


GHIDRA_FUNC_PREFIX = 'FUN_'
CUSTOM_AUTO_FUNC_PREFIX = 'f_p__'
CUSTOM_AUTO_THREAD_FUNC_PREFIX  = 'f_p__TS__'

OP_TYPE_PUSH_REGISTER = 512
#OP_TYPE_CALL_REGISTER_NO_REFERENCE = 516
#OP_TYPE_CALL_REGISTER_WITH_REFERENCE = 8708
OP_TYPE_CALL_STATIC_FUNCTION = 8256
OP_TYPE_CALL_DATA_VARIABLE = 8324 # with or without known reference
#OP_TYPE_CALL_STACK_VARIABLE = 4202500



def main():

    print('{:s}\n{:s}'.format('=' * 100, 'Function_Preview Script Starting'))


    
    #
    # rename thread start functions
    # do this first so to potentially create new functions 
    # because often the thread start functions don't get 
    # analyzed by default
    #

    # get initial thread starts
    threadRootsList = Get_Thread_Roots()

    # rename thread starts with auto name
    for rootEa in threadRootsList:
        newFuncName = '{:s}{:s}{:s}'.format(CUSTOM_AUTO_THREAD_FUNC_PREFIX , GHIDRA_FUNC_PREFIX, rootEa.toString())

        curFunc = getFunctionAt(rootEa)
        if curFunc == None:
            createFunction(rootEa, newFuncName)
        else:
            curFunc.setName(newFuncName, ghidra.program.model.symbol.SourceType.USER_DEFINED)


    
    #
    # get list of all functions to rename and leaf nodes.  Get leaf nodes by
    # checking if each function is a parent. leaf nodes will not be a parent functions
    # ignore library / thunk functions
    #


    # start with all unidentified functions, i.e. all functions that start with the
    # Ghidra standard function prefix or this scripts custom function prefix
    # assume any other function name was either named from a library signature or manually by
    # a user, and you don't want to overwrite those function names.  Also ignore thunk functions
    # skip thread start functions because having all of the target functionality added to the 
    # thread function name is generally overkill.
    funcList = [f for f in currentProgram.getListing().getFunctions(True) if f.getName().startswith( (GHIDRA_FUNC_PREFIX, CUSTOM_AUTO_FUNC_PREFIX) ) and not f.getName().startswith(CUSTOM_AUTO_THREAD_FUNC_PREFIX)]
    funcList = [f for f in funcList[:] if f.isThunk() == False]

    # identify all parent nodes within unidentified function set
    parentNodes = set()
    for curFunc in funcList:
        curParentNodes = curFunc.getCallingFunctions(monitor)
        parentNodes.update(curParentNodes)


    # store all functions that are not a parent as a leaf node
    leafNodes = [f for f in funcList if f not in parentNodes ]


    
    #
    # recusively apply renaming to unidentified functions starting from leaf nodes
    # up through parents.  This will ensure child functionality is propagated
    # up through the parent functions
    #
    # do recursively until no changes are made.  This will ensure that all of the
    # child function capabilities are propagated up through the parents
    #
    while True:
        funcRenamedCount = 0
        nodesTraversed = set()
        curNodes = leafNodes[:]
        while True:

            # rename each function in current level of nodes
            parentNodes = set()
            for curFunc in curNodes:

                # rename function and track if new name is actually different than old name
                # this count is used to determine when to finish recursively renaming functions
                oldFuncName = curFunc.getName()
                newFuncNameProposed = Build_New_Func_Name(curFunc)
                curFunc.setName(newFuncNameProposed, ghidra.program.model.symbol.SourceType.USER_DEFINED)
                newFuncNameActual = curFunc.getName()
                if oldFuncName != newFuncNameActual: funcRenamedCount += 1

                # add current function into nodesTraversed so you can check for infinite loops
                nodesTraversed.add(curFunc)

                # get parent nodes that are in the unidentified functions list
                # ignore any parents not in that list assuming they are library
                # calls or other functions we don't want to overwrite
                curParentNodes = curFunc.getCallingFunctions(monitor)
                parentNodes.update( curParentNodes & set(funcList) )

                # remove any functions from the nodesTraversed list to eliminate infinite loops
                parentNodes = parentNodes - nodesTraversed


            # inner whie loop exit condition
            if len(parentNodes) == 0: break

            # copy parentNodes to curNodes to rename in next iteration of loop
            curNodes = parentNodes.copy()

        # outer while loop exit condition
        if funcRenamedCount == 0: break


    print('{:s}\n{:s}'.format('Function_Preview Script Completed', '=' * 100))




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






def Get_Thread_Roots():
    '''
    returns a list of addresses of the root functions for all threads
    found in the program
    '''

    # list of  thread creation functions
    funcNamesList = ['CreateThread', '_beginthreadex', '__beginthreadex', '_beginthread', '__beginthread']

    # go through every thread create option
    threadStartEaSet = set()
    for funcName in funcNamesList:
        # set thread start argument because it is different number based on API used
        argIndex = 1 if funcName.lstrip('_') == 'beginthread' else 3

        # get list of API references
        funcList = list(currentProgram.getSymbolTable().getSymbols(funcName))
        if len(funcList) == 0: continue

        # get all references to target function
        funcReferences = funcList[0].getReferences()

        for ref in funcReferences:

            # if reference location is a call instruction
            if 'call' not in ref.getReferenceType().getName().lower(): continue

            # find the actual thread start function
            refInstr = getInstructionAt(ref.getFromAddress())
            mnemInstr = Get_Prev_Target_Instruction(refInstr, 'push', argIndex, 10)
            if mnemInstr == None: continue


            # get thread start address
            if mnemInstr.getOperandType(0) == OP_TYPE_PUSH_REGISTER:
                # if thread start was a register, look for root address where register
                # value was set
                regStr = mnemInstr.getRegister(0).getName().lower()
                for i in range(5):
                    mnemInstr = Get_Prev_Target_Instruction(mnemInstr, 'mov', 1, 10)
                    if mnemInstr == None: break

                    if mnemInstr.getRegister(0).getName().lower() == regStr:
                        rootEa = mnemInstr.getOperandReferences(1)[0].getToAddress()
                        if getFunctionContaining(rootEa) != None: threadStartEaSet.add(rootEa)

                        break
            else:
                # assume normal push offset
                rootEa = mnemInstr.getOperandReferences(0)[0].getToAddress()
                threadStartEaSet.add(rootEa)



    return threadStartEaSet



def Build_New_Func_Name(func):
    '''
    function will return a string for naming functionality based on desired
    functionality found
    functionality is split into categories.  Each category has a
    single identifier to indicate a generic capability for that category
    e.g. netwCSR = network category, connect, send, and receive capabilities
    '''

    # use ordered dictionary so that categories are always printed
    # in the same order
    categoryNomenclatureDict = collections.OrderedDict()
    categoryNomenclatureDict['netw'] = ['b','c','l','s','r','t','m']
    categoryNomenclatureDict['reg'] = ['h','r','w','d']
    categoryNomenclatureDict['file'] = ['h','r','w','d','c','m','e']
    categoryNomenclatureDict['proc'] = ['h','e','c','t','r','w']
    categoryNomenclatureDict['serv'] = ['h','c','d','s','r','w']
    categoryNomenclatureDict['thread'] = ['c','o','s','r']
    categoryNomenclatureDict['str'] = ['c']



    # for dictionary, list only the basenames, leave off prefixes of '_'
    # and any suffix such as Ex, ExA, etc.  These will be stripped from
    # the functions calleed to account for all variations
    apiPurposeDict = {
        'socket':'netwB',

        #WSAStartup':'netwC',
        'connect':'netwC',
        'InternetOpen':'netwC',
        'InternetConnect':'netwC',
        'InternetOpenURL':'netwC',
        'HttpOpenRequest':'netwC',
        'WinHttpConnect':'netwC',
        'WinHttpOpenRequest':'netwC',

        'bind':'netwL',
        'listen':'netwL',
        'accept':'netwL',

        'send':'netwS',
        'sendto':'netwS',
        'InternetWriteFile':'netwS',
        'HttpSendRequest':'netwS',
        'WSASend':'netwS',
        'WSASendTo':'netwS',
        'WinHttpSendRequest':'netwS',
        'WinHttpWriteData':'netwS',

        'recv':'netwR',
        'recvfrom':'netwR',
        'InternetReadFile':'netwR',
        'HttpReceiveHttpRequest':'netwR',
        'WSARecv':'netwR',
        'WSARecvFrom':'netwR',
        'WinHttpReceiveResponse':'netwR',
        'WinHttpReadData':'netwR',
        'URLDownloadToFile':'netwR',

        'inet_addr':'netwM',
        'htons':'netwM',
        'htonl':'netwM',
        'ntohs':'netwM',
        'ntohl':'netwM',

        # to common due to error conditions
        # basically becomes background noise
        #
        #'closesocket':'netwT',
        #'shutdown':'netwT',


        'RegOpenKey':'regH',

        'RegQueryValue':'regR',
        'RegGetValue':'regR',
        'RegEnumValue':'regR',

        'RegSetValue':'regW',
        'RegSetKeyValue':'regW',

        'RegDeleteValue':'regD',
        'RegDeleteKey':'regD',
        'RegDeleteKeyValue':'regD',

        'RegCreateKey':'regC',

        'CreateFile':'fileH',
        'fopen':'fileH',

        'fscan':'fileR',
        'fgetc':'fileR',
        'fgets':'fileR',
        'fread':'fileR',
        'ReadFile':'fileR',

        'flushfilebuffers':'fileW',
        'fprintf':'fileW',
        'fputc':'fileW',
        'fputs':'fileW',
        'fwrite':'fileW',
        'WriteFile':'fileW',

        'DeleteFile':'fileD',

        'CopyFile':'fileC',

        'MoveFile':'fileM',

        'FindFirstFile':'fileE',
        'FindNextFile':'fileE',

        'strcmp':'strC',
        'strncmp':'strC',
        'stricmp':'strC',
        'wcsicmp':'strC',
        'mbsicmp':'strC',
        'lstrcmp':'strC',
        'lstrcmpi':'strC',

        'OpenService':'servH',

        'QueryServiceStatus':'servR',
        'QueryServiceConfig':'servR',

        'ChangeServiceConfig':'servW',
        'ChangeServiceConfig2':'servW',

        'CreateService':'servC',

        'DeleteService':'servD',

        'StartService':'servS',

        'CreateToolhelp32Snapshot':'procE',
        'Process32First':'procE',
        'Process32Next':'procE',

        'OpenProcess':'procH',

        'CreateProcess':'procC',
        'CreateProcessAsUser':'procC',
        'CreateProcessWithLogon':'procC',
        'CreateProcessWithToken':'procC',
        'ShellExecute':'procC',

        # to common due to error conditions
        # basically becomes background noise
        #
        #'ExitProcess':'procT',
        #'TerminateProcess':'procT',

        'ReadProcessMemory':'procR',

        'WriteProcessMemory':'procW',

        'CreateThread':'threadC',
        'beginthread':'threadC',
        'beginthreadex':'threadC', # EXCEPTION: include ex because it's lowercase and won't be caught by case-sensitive suffix stripper routine later

        'OpenThread':'threadO',

        'SuspendThread':'threadS',

        'ResumeThread':'threadR',

    }


    # get function info
    funcOrigName = func.getName()
    funcAddressSet = func.getBody()

    # get count of number of times current function is called
    refToCount = getSymbolAt(func.getEntryPoint()).getReferenceCount()

    # get all calls in current function
    callList = []
    curInstr = getInstructionAt(func.getEntryPoint())
    while ( (curInstr != None) and (funcAddressSet.contains(curInstr.getAddress()) == True) ):
        if curInstr.getMnemonicString().lower() == 'call': callList.append(curInstr)
        curInstr = curInstr.getNext()



    # remove any recursive calls, otherwise any functionality in function
    # will also be treated as child functionality and appended to child
    # portion of name
    recursiveList = []
    for curCall in callList:
        curOpRef = curCall.getOperandReferences(0)

        # skip calls to registers or any type that doesn't store adddress information
        if len(curOpRef) == 0: continue

        # check operand reference to make sure it's not recursive
        if curOpRef[0].getToAddress().equals(func.getEntryPoint()) == True:
            recursiveList.append(curCall)
    callList = list(set(callList) - set(recursiveList))



    # if no calls, return appropriate response
    if len(callList) == 0:
        # check if functiton is a thunk
        if func.isThunk() == True:
            callList.append(getInstructionAt(func.getEntryPoint()))
        else:
            # otherwise, return zero call
            return '{:s}zc_{:s}{:s}__xref_{:02d}'.format(CUSTOM_AUTO_FUNC_PREFIX, GHIDRA_FUNC_PREFIX, func.getEntryPoint().toString(), refToCount)


    #
    # if calls are found, try to identify functionality
    #
    apiUsed = set()

    # process calls with external reference
    for curCall in callList:
        if curCall.getExternalReference(0) != None:
            # extract API basename to ignore prefix/suffix, e.g. _, Ex, ExA
            curApiName = curCall.getExternalReference(0).getLabel()
            pattern = '^(?:FID_conflict:)?(?:_)*(?P<baseName>.+?)(?:A|W|Ex|ExA|ExW)?(?:@[a-fA-F0-9]+)?$'
            match = re.search(pattern, curApiName)
            curApiName = match.group('baseName')

            # add current API name to summary set
            apiUsed.add(curApiName)


    # process calls to statically linked functions
    for curCall in callList:
        if curCall.getOperandType(0) == OP_TYPE_CALL_STATIC_FUNCTION:
            curApiName = getFunctionAt(curCall.getReferencesFrom()[0].getToAddress()).getName()
            if curApiName.startswith((GHIDRA_FUNC_PREFIX, CUSTOM_AUTO_FUNC_PREFIX, CUSTOM_AUTO_THREAD_FUNC_PREFIX )) == False:
                # extract API basename to ingnore prefix/suffix, e.g. _, Ex, ExA
                pattern = '^(?:FID_conflict:)?(?:_)*(?P<baseName>.+?)(?:A|W|Ex|ExA|ExW)?(?:@[a-fA-F0-9]+)?$'
                match = re.search(pattern, curApiName)
                curApiName = match.group('baseName')

                # add current API name to summary set
                apiUsed.add(curApiName)


    # process calls to function pointers stored in data variables
    for curCall in callList:
        if curCall.getOperandType(0) == OP_TYPE_CALL_DATA_VARIABLE:
            curOpEa = curCall.getReferencesFrom()[0].getToAddress()
            curData = getDataAt(curOpEa)

            # getDataAt should return data object for defined and undefined data,
            # but there seems to be a bug and sometimes returns None on undefined data
            if curData == None: curData = getUndefinedDataAt(curOpEa)

            # get the data variable label
            if curData.getExternalReference(0) != None:
                curApiName = curData.getExternalReference(0).getLabel()
            else:
                curApiName = curData.getLabel()


            if curApiName.lower().startswith(('dat_', 'byte_', 'word_', 'dword_', 'qword_')) == False:
                # extract API basename to ingnore prefix/suffix, e.g. _, Ex, ExA
                pattern = '^(?:FID_conflict:)?(?:_)*(?P<baseName>.+?)(?:A|W|Ex|ExA|ExW)?(?:@[a-fA-F0-9]+)?$'
                match = re.search(pattern, curApiName)
                curApiName = match.group('baseName')

                # add current API name to summary set
                apiUsed.add(curApiName)




    # map API's called to functionality to use for naming
    implementedApiPurpose = set()
    for entry in apiUsed:
        implementedApiPurpose.add(apiPurposeDict.get(entry))


    # identify functionality from child functions already renamed by this script
    # this will allow api usage to propagate up to the root function
    childFunctionImplementedApiPurpose = dict()
    for curCall in callList:
        if curCall.getOperandType(0) == OP_TYPE_CALL_STATIC_FUNCTION:
            curApiName = getFunctionAt(curCall.getReferencesFrom()[0].getToAddress()).getName()
            if curApiName.startswith(CUSTOM_AUTO_FUNC_PREFIX) == True:

                # pull out api capabilities based on naming convention
                for category in categoryNomenclatureDict:
                    pattern = category + '_' + '([a-zA-Z]+)+_?([a-zA-Z]+)?'
                    match = re.search(pattern, curApiName)

                    # if category is found, save into results
                    if match is not None:
                        apiPurpose = set()
                        if match.group(1) is not None: apiPurpose.update(list(match.group(1).lower()))
                        if match.group(2) is not None: apiPurpose.update(list(match.group(2).lower()))
                        if category in childFunctionImplementedApiPurpose:
                            childFunctionImplementedApiPurpose[category].update(apiPurpose)
                        else:
                            childFunctionImplementedApiPurpose[category] = apiPurpose



    #
    # create function name based on API functionality found
    #

    newFuncNamePurpose = ''

    # for each category, loop through all the nomenclature symbols
    # if the symbol is found in the current function, add it to the parent string
    # if the symbol is found in a child function, add it to child string
    for category in categoryNomenclatureDict:

        # build the symbol list for the parent function
        parentStr = ''
        for symbol in categoryNomenclatureDict[category]:
            if (category + symbol.upper()) in implementedApiPurpose:
                parentStr += symbol.upper()


        # build the symbol list for the child functions
        childStr = ''
        if category in childFunctionImplementedApiPurpose:
            for symbol in categoryNomenclatureDict[category]:
                if symbol.lower() in childFunctionImplementedApiPurpose[category]:
                    childStr += symbol.lower()

        # combine the parent / child symbol list into one final string
        if (len(parentStr) > 0) or (len(childStr) > 0):
            newFuncNamePurpose = newFuncNamePurpose + category
            if len(parentStr) > 0: newFuncNamePurpose = newFuncNamePurpose + '_' + parentStr
            if len(childStr) > 0: newFuncNamePurpose = newFuncNamePurpose + '_' + childStr
            newFuncNamePurpose = newFuncNamePurpose + '__'






    # build the final function name
    if len(newFuncNamePurpose) > 0:
        # targeted functionality found
        finalFuncName = '{:s}{:s}xref_{:02d}_{:s}'.format(CUSTOM_AUTO_FUNC_PREFIX, newFuncNamePurpose, refToCount, func.getEntryPoint().toString())
    else:
        # no targeted functionality identified
        finalFuncName = '{:s}{:s}{:s}__xref_{:02d}'.format(CUSTOM_AUTO_FUNC_PREFIX, GHIDRA_FUNC_PREFIX, func.getEntryPoint().toString(), refToCount)



    return finalFuncName






if __name__ == '__main__':
    main()

