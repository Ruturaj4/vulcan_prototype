# ghidra static analyzer

import re
import os
import json
import sys
# to decompile
from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
# to rename function
from ghidra.program.model.symbol import SourceType
# to trace basic blocks
from ghidra.program.model.block import BasicBlockModel
from ghidra.program.model.pcode import HighFunctionDBUtil

from ghidra.program.database.code import DataDB

# globals
IFC = DecompInterface()
IFC.setOptions(DecompileOptions())
IFC.openProgram(currentProgram)
# turn on detection extention
EXT = int(getScriptArgs()[0])
# enable decompiler on objects
DECOMP = int(getScriptArgs()[1])
# ref manager is used to find references
REFMANAGER = currentProgram.referenceManager
# save owner per instruction
instruction_map = {}
# global dict to store detected instructions and owners
metadata = {".global":{}}

# add main function symbol in binary (if not present)
def find_main():
    try:
        entryfunction = getGlobalFunctions("entry")[0]
    except:
        # if binary has symbols
        if getGlobalFunctions("_start"):
            entryfunction = getGlobalFunctions("_start")[0]
        else:
            return 0
    res = IFC.decompileFunction(entryfunction, 60, monitor)
    m = re.search("__libc_start_main\((.+?),", res.getCCodeMarkup().toString())
    if m.group(1)[0] != "main":
        getGlobalFunctions(m.group(1))[0].setName("main", SourceType.ANALYSIS)
    return 1

def get_basicblocks():
    # for static blocks
    blockiterator = BasicBlockModel(currentProgram).getCodeBlocks(monitor)
    fun_blocks = {}

    def add_block(function, min_address, max_address):
        if function not in fun_blocks:
             fun_blocks[function] = []
        fun_blocks[function].append([min_address,max_address])

    # For each block, look through the function list until we find a match
    def basicblocks():
        while blockiterator.hasNext():
            block = blockiterator.next()
            min_address = block.getMinAddress()
            max_address = block.getMaxAddress()
            function = getFirstFunction()
            found = False

            # Search functions until we find a match or run out of functions
            while function is not None:
                b = function.getBody()
                if b.contains(min_address) and b.contains(max_address):
                    add_block(function, min_address, max_address)
                    found=True
                    break
                # Update function to next and loop again
                function = getFunctionAfter(function)
    basicblocks()
    return fun_blocks

# get all user defined/called functions
def get_functions():
    # functions = set()
    ignore_funs = {"__xstat", "__lxstat", "printf", "malloc", "calloc", "realloc", "free", \
    "_init" , "puts", "__errno_location", "register_tm_clones", "__libc_csu_init", "_start", \
    "_dl_relocate_static_pie", "deregister_tm_clones", "__libc_csu_fini", "__do_global_dtors_aux",\
    ".annobin_init.c", "_fini", "frame_dummy", "fini", "entry", "_INIT_0", "_DT_INIT", "_DT_FINI", "_FINI_0",\
    "__libc_start_main", "__gmon_start__"}
    functions = currentProgram.getFunctionManager().getFunctions(True)
    return [f for f in functions if str(f) not in ignore_funs]

# predict type of object
def predictdtype(var):
    # add more datatypes if necessary
    if "array" in str(type(var.getDataType())).lower() or "string" in str(type(var.getDataType())).lower():
        return "ARRAY"
    elif "pointer" in str(type(var.getDataType())).lower():
        return "PTR"
    elif "struct" in str(type(var.getDataType())).lower():
        return "struct"
    # predict pointer
    elif isinstance(var.getDataType(), ghidra.program.model.data.Undefined8DataType):
        return "PTR"
    else:
        return "scalar"

def unpred_ownertype(var):
    if "array" in str(type(var.getDataType())).lower() or "string" in str(type(var.getDataType())).lower():
        return "ARRAY"
    elif "pointer" in str(type(var.getDataType())).lower():
        return "PTR"
    elif "struct" in str(type(var.getDataType())).lower():
        return "struct"
    else:
        return "scalar"

# cat 1/2/3
def inst_category(inst, ownertype):
    # III: pointer move - 0
    # IV: pointer boundcheck - 1
    # V: array boundcheck - 2
    if ownertype == "PTR":
        return "0"
    else:
        return "2"

# load/store reg,imm
def inst_type(inst):
    # load reg - 0
    # store imm - 1
    # store reg - 2
    if inst.getRegister(0) and inst.getRegister(1):
        pass
    elif inst.getRegister(0) and "DATA" in str(inst.getOperandRefType(1)):
        pass
    # load reg - 0
    elif inst.getRegister(0):
        return "0"
    else:
        # store reg - 2
        if inst.getRegister(1):
            return "2"
        # store imm - 1
        return "1"

# get globally defined objects
def get_data_symbols(functions):
    # these are the symbols which are defined in the data section
    symbols = set(currentProgram.getSymbolTable().getAllSymbols(True))
    mem = currentProgram.getMemory()
    # symbols to ignore
    ignore_symbols = {"__dso_handle", "DAT_00402010"}
    # get .rodata, .bss and .data section addrsses
    rodata_start, rodata_end = mem.getBlock(".rodata").getStart(), mem.getBlock(".rodata").getEnd()
    bss_start, bss_end = mem.getBlock(".bss").getStart(), mem.getBlock(".bss").getEnd()
    data_start, data_end = mem.getBlock(".data").getStart(), mem.getBlock(".data").getEnd()
    for s in symbols:
        if str(s) in ignore_symbols:
            continue
        if not ((s.address > rodata_start and s.address <= rodata_end) \
        or (s.address > bss_start and s.address <= bss_end) \
        or (s.address > data_start and s.address <= data_end)):
            continue
        if not str(s.getSymbolType()) == "Label":
            continue
        if not isinstance(s.getObject(), DataDB):
            continue
        address = str(s.getAddress()).lstrip("0")
        size = str(s.getObject().getLength())
        namespace = ".global"
        dtype = s
        ownertype = predictdtype(s.getObject())
        addresses = [x.getFromAddress() for x in s.getReferences()]
        # predict actual type
        try:
            if s.getObject().getParent():
                # decide their namespace - it will be same as the their parent function
                if len({getFunctionContaining(x.getFromAddress()) for x in s.getReferences()})==1:
                    namespace = ".global_"+str(getFunctionContaining(s.getReferences()[0].getFromAddress()))
                if s.getObject().getParent().isArray():
                    dtype = s.getObject().getParent().getPathName()
                    size = str(s.getObject().getParent().getLength())
                    address = str(s.getObject().getParent().getAddress()).lstrip("0")
                ownertype = predictdtype(s.getObject().getParent())
        except:
            pass
        obj_metadata = {"owner":namespace + "_" + str(dtype),"ownertype":ownertype, "address":address, "size":size}
        metadata[".global"][address] = obj_metadata
        for ref in s.getReferences():
            # add instruction to instruction map
            # adding this before filters to collect all instructions
            inst = getInstructionAt(ref.getFromAddress())
            if ownertype != "PTR" or ownertype != "ARRAY":
                continue
            if inst == None:
                continue
            if "MOV" not in inst.getMnemonicString():
                continue
            if str(ref.getFromAddress()) == "Entry Point":
                continue
            if str(ref.getReferenceType()) not in ["READ", "WRITE"]:
                continue
            # this will avoid incorrect detection for instructions like mov reg, [reg]
            if str(inst.getOperandRefType(0)) == "READ_WRITE":
                continue
            # add instruction to instruction map
            instruction_map[ref.getFromAddress()]= namespace + "_" + str(dtype), ownertype, size, obj_metadata
            fun_name = getFunctionContaining(ref.getFromAddress())
            if not fun_name:
                continue
            if "RBP" in str(getInstructionAt(fun_name.getEntryPoint())):
                adjust_off = currentProgram.getLanguage().getLanguageDescription().getSize() >> 3
            else:
                adjust_off = 0
            # print(ref.getFromAddress())
            # print(str(ref.getReferenceType()))
            inst = getInstructionAt(ref.getFromAddress())
            category = inst_category(inst, ownertype)
            itype = inst_type(inst)
            # print(inst.getOperandRefType(0))
            # print(inst.getOperandRefType(1))
            # print(ref.getFromAddress())
            if str(fun_name) in map(str, functions):
                if str(fun_name) not in metadata:
                    metadata[str(fun_name)] = {"variables":{}, "addresses":{}, "entry":0, "exit":0, "stack":0, "parameter":0, "rbp_rsp":adjust_off}
                metadata[str(fun_name)]["addresses"][str(ref.getFromAddress()).lstrip("0")] = \
                {"owner":namespace + "_" + str(dtype), "category":category, "type":itype, "obj_metadata":obj_metadata}

def get_structure_members(function, var, structvar, name, offset, adjust_off, eoff):
    # structvar is required to parse the structure
    # the main var will be same for every recursive call
    # as it governs the identification of structure reference
    # because it is of type localvariable
    for member in structvar.getDataType().getDefinedComponents():
        offset = offset + member.getOffset()
        if offset > eoff:
            continue
        ownertype = predictdtype(member)
        ownertype_unpred = unpred_ownertype(member)
        size = member.getLength()
        owner = str(function.getName()) + "_" + name + "_" + str(member.getFieldName())
        if ownertype == "struct":
            get_structure_members(function, var, member, owner, offset, adjust_off, eoff)
        else:
            obj_metadata = {"owner":owner, "offset":offset, "dtype":str(member).replace(" ", ""), "ownertype":ownertype, "size":size, "ownertype_unpred":ownertype_unpred}
            metadata[str(function)]["variables"][offset] = obj_metadata
            # if ownertype == "scalar":
            #     continue
            for ref in list(REFMANAGER.getReferencesTo(var)):
                if ref.getToAddress().getOffset()+adjust_off in range(offset+size-1, offset-1, -1):
                    if getInstructionAt(ref.getFromAddress()) == None:
                        continue
                    instruction_map[ref.getFromAddress()]=owner,ownertype,size, obj_metadata
                    if "MOV" not in getInstructionAt(ref.getFromAddress()).getMnemonicString():
                        continue
                    inst = getInstructionAt(ref.getFromAddress())
                    category = inst_category(inst, ownertype)
                    itype = inst_type(inst)
                    if (str(ref.getReferenceType()) in ["WRITE", "READ"]) and ownertype != "scalar":
                        metadata[str(function)]["addresses"][str(ref.getFromAddress()).lstrip("0")] = \
                        {"owner":owner, "category":category, "type":itype, "obj_metadata":obj_metadata}

def get_local_variables(function, adjust_off):
    # adjust_off = function.getStackFrame().getParameterOffset()
    variables = function.getAllVariables()
    for var in variables:
        # stack offset
        # print(var)
        # print(var.	isRegisterVariable())
        if var.isStackVariable():
            offset = var.getStackOffset() + adjust_off
        else:
            continue
        if not offset < 0 and offset not in range(adjust_off + function.getStackFrame().getParameterOffset(), \
        int(metadata[str(function)]["parameter"])):
            continue
        ownertype = predictdtype(var)
        ownertype_unpred = unpred_ownertype(var)
        # print(ownertype_unpred)
        size = var.getLength()
        owner = str(function.getName()) + "_" + str(var.getName())
        # predict structure elements
        if ownertype == "struct":
            get_structure_members(function, var, var, owner, offset, adjust_off, offset+size)
        else:
            obj_metadata = {"owner":owner, "offset":offset, "dtype":str(var.getDataType().getName()).replace(" ", ""), "ownertype":ownertype, "size":size, "ownertype_unpred":ownertype_unpred}
            metadata[str(function)]["variables"][offset] = obj_metadata
            # if ownertype == "scalar":
            #     continue
            for ref in list(REFMANAGER.getReferencesTo(var)):
                if getInstructionAt(ref.getFromAddress()) == None:
                    continue
                instruction_map[ref.getFromAddress()]=owner,ownertype,size,obj_metadata
                if "MOV" not in getInstructionAt(ref.getFromAddress()).getMnemonicString():
                    continue
                inst = getInstructionAt(ref.getFromAddress())
                category = inst_category(inst, ownertype)
                itype = inst_type(inst)
                if str(ref.getReferenceType()) in ["WRITE", "READ"] and ownertype != "scalar":
                    metadata[str(function)]["addresses"][str(ref.getFromAddress()).lstrip("0")] = \
                    {"owner":owner, "category":category, "type":itype, "obj_metadata":obj_metadata}

# pointer flow analysis
def predict_owners(block, function):
    cur = block[0]
    # a dic of registers and pointers to be tracked
    regs = {}
    while cur < block[1]:
        owner, ownertype, size, obj_metadata = "", "", "", ""
        inst = getInstructionAt(cur)
        if not inst:
            cur = cur.next()
            continue
        # print("{}: {}".format(cur, inst))
        # return if return instruction
        if "RET" in inst.getMnemonicString():
            return
        if "LEAVE" in inst.getMnemonicString():
            return
        # call may change regs according to convention
        if "CALL" in inst.getMnemonicString():
            regs = {}
            cur = cur.next()
            continue
        if cur in instruction_map:
            owner, ownertype, size, obj_metadata = instruction_map[cur][0], instruction_map[cur][1], instruction_map[cur][2], instruction_map[cur][3]
        # print(owner)
        if "MOV" in inst.getMnemonicString():
            if ownertype == "PTR" or ownertype == "ARRAY":
                if inst.getRegister(0) and inst.getRegister(1):
                    if inst.getRegister(1).getBaseRegister() in regs:
                        regs[inst.getRegister(0).getBaseRegister()] = regs[inst.getRegister(1).getBaseRegister()]
                elif inst.getRegister(0) and "DATA" in str(inst.getOperandRefType(1)):
                    if inst.getRegister(0).getBaseRegister() in regs:
                        del regs[inst.getRegister(0).getBaseRegister()]
                elif inst.getRegister(0):
                    # if register size is less than 64 bytes then remove it
                    if inst.getRegister(0).getMinimumByteSize() <= 4:
                        if inst.getRegister(0).getBaseRegister() in regs:
                            del regs[inst.getRegister(0).getBaseRegister()]
                    # otherwise there is a chance that the dereferenced value contains a pointer
                    else:
                        if str(size) == "8":
                            regs[inst.getRegister(0).getBaseRegister()] = owner
            else:
                if inst.getRegister(0) and inst.getRegister(1):
                    if inst.getRegister(1).getBaseRegister() in regs:
                        regs[inst.getRegister(0).getBaseRegister()] = regs[inst.getRegister(1).getBaseRegister()]
                elif inst.getRegister(0) and "DATA" in str(inst.getOperandRefType(1)):
                    if inst.getRegister(0).getBaseRegister() in regs:
                        del regs[inst.getRegister(0).getBaseRegister()]
                elif inst.getRegister(0):
                    predicted = False
                    # predict owner using offset used in instruction
                    if EXT:
                        for off,v in metadata[str(function)]["variables"].items():
                            # don't predict scalars
                            if v["ownertype"] == "scalar":
                                continue
                            if hex(v["offset"]) == list(map(str, inst.getOpObjects(1)))[-1]:
                                metadata[str(function)]["addresses"][str(cur).lstrip("0")] = \
                                {"owner":v["owner"],"category":inst_category(inst, v["ownertype"]), "type":inst_type(inst), "obj_metadata":v}
                                predicted = True
                                break
                    # predict owner using saved register map
                    if not predicted:
                        registers = [i for i in inst.getOpObjects(1) if type(i) == ghidra.program.model.lang.Register]
                        for i in registers:
                            if i in regs:
                                # check if local pointer
                                for off,v in metadata[str(function)]["variables"].items():
                                    # todo: remove this
                                    if v["ownertype"] == "scalar":
                                        continue
                                    if v["owner"] == str(regs[i]):
                                        obj_metadata = v
                                        break
                                # check if global pointer
                                else:
                                    for addr,v in metadata[".global"].items():
                                        # todo: remove this
                                        if v["ownertype"] == "scalar":
                                            continue
                                        if v["owner"] == str(regs[i]):
                                            obj_metadata = v
                                            break
                                metadata[str(function)]["addresses"][str(cur).lstrip("0")] = \
                                {"owner":str(regs[i]), "category":"1", "type":inst_type(inst), "obj_metadata":obj_metadata}
                                predicted = True
                                break
                    # unknown if this instruction is "unowned"
                    if not predicted and ownertype != "scalar":
                        metadata[str(function)]["addresses"][str(cur).lstrip("0")] = \
                        {"owner":"unknown", "category":"4", "type":inst_type(inst), "obj_metadata":"unknown"}
                    # remove the register as it may no longer contain the pointer object
                    if inst.getRegister(0).getBaseRegister() in regs:
                        del regs[inst.getRegister(0).getBaseRegister()]
                # mov mem, reg/imm instructions
                else:
                    predicted = False
                    # predict owner using offset used in instruction
                    if EXT:
                        for off,v in metadata[str(function)]["variables"].items():
                            # don't predict scalars
                            if v["ownertype"] == "scalar":
                                continue
                            if hex(v["offset"]) == list(map(str, inst.getOpObjects(0)))[-1]:
                                metadata[str(function)]["addresses"][str(cur).lstrip("0")] = \
                                {"owner":v["owner"],"category":inst_category(inst, v["ownertype"]), "type":inst_type(inst), "obj_metadata":v}
                                predicted = True
                                break
                    # predict owner using saved register map
                    if not predicted:
                        registers = [i for i in inst.getOpObjects(0) if type(i) == ghidra.program.model.lang.Register]
                        for i in registers:
                            if i in regs:
                                # check if local pointer
                                for off,v in metadata[str(function)]["variables"].items():
                                    # todo: remove this
                                    if v["ownertype"] == "scalar":
                                        continue
                                    if v["owner"] == str(regs[i]):
                                        obj_metadata = v
                                        break
                                # check if global pointer
                                else:
                                    for addr,v in metadata[".global"].items():
                                        # todo: remove this
                                        if v["ownertype"] == "scalar":
                                            continue
                                        if v["owner"] == str(regs[i]):
                                            obj_metadata = v
                                            break
                                metadata[str(function)]["addresses"][str(cur).lstrip("0")] = \
                                {"owner":str(regs[i]), "category":"1", "type":inst_type(inst), "obj_metadata":obj_metadata}
                                predicted = True
                                break
                    # unknown if this instruction is "unowned"
                    if not predicted and ownertype != "scalar":
                        metadata[str(function)]["addresses"][str(cur).lstrip("0")] = \
                        {"owner":"unknown","category":"4", "type":inst_type(inst), "obj_metadata":"unknown"}

        elif "LEA" in inst.getMnemonicString():
            if owner:
                if ownertype == "ARRAY":
                    regs[inst.getRegister(0).getBaseRegister()] = owner
            else:
                # if owner is unknown then remove (as there's no other choice)
                if inst.getRegister(0).getBaseRegister() in regs:
                    del regs[inst.getRegister(0).getBaseRegister()]
        elif any(x in inst.getMnemonicString() for x in ["ADD", "SUB"]):
            if inst.getRegister(0) and inst.getRegister(1):
                if inst.getRegister(1).getBaseRegister() in regs:
                    regs[inst.getRegister(0).getBaseRegister()] = regs[inst.getRegister(1).getBaseRegister()]
        cur = cur.next()

def storesymbols(function):
    try:
        res = IFC.decompileFunction(function, 60, monitor)
        high_func = res.getHighFunction()
        lsm = high_func.getLocalSymbolMap()
        symbols = lsm.getSymbols()
        HighFunctionDBUtil.commitLocalsToDatabase(high_func, SourceType.ANALYSIS)
    except AttributeError:
        return

def function_iterator(fun_blocks, functions):
    for function in functions:
        if not function in fun_blocks:
            continue
        # function boundary
        fun_entry = function.getEntryPoint()
        fun_exit = fun_blocks[function][-1][-1]
        # function stack size
        # print(function)
        if "RBP" in str(getInstructionAt(fun_entry)) and "RBP" in str(getInstructionAt(fun_entry).getNext()):
            adjust_off = currentProgram.getLanguage().getLanguageDescription().getSize() >> 3
        else:
            adjust_off = 0
        stack_size = function.getStackFrame().getLocalSize() - adjust_off
        # parameter size
        parameter_size = function.getStackFrame().getParameterSize() + adjust_off + function.getStackFrame().getParameterOffset()
        if str(function) in metadata:
            metadata[str(function)]["entry"] = str(fun_entry).lstrip("0")
            metadata[str(function)]["exit"] = str(fun_exit).lstrip("0")
            metadata[str(function)]["parameter"] = str(parameter_size)
            metadata[str(function)]["stack"] = str(stack_size)
            metadata[str(function)]["rbp_rsp"] = str(adjust_off)
        else:
            metadata[str(function)] = {"variables":{}, "addresses":{}, "parameter":str(parameter_size), "rbp_rsp":str(adjust_off), \
            "stack":str(stack_size), "entry":str(fun_entry).lstrip("0"), "exit":str(fun_exit).lstrip("0")}
        # apply decompiler if enabled
        if DECOMP:
            storesymbols(function)
        # get function local variables
        get_local_variables(function, adjust_off)
        for block in fun_blocks[function]:
            predict_owners(block, function)

def main():
    # add main function symbol in binary (if not present)
    # if not find_main():
        # exit()
    # find static basic blocks
    fun_blocks = get_basicblocks()
    # get all user defined/called functions
    functions = get_functions()
    # get globally defined objects
    get_data_symbols(functions)
    # iterate through functions
    function_iterator(fun_blocks, functions)

def print_metadata():
    path, file = os.path.split(currentProgram.getExecutablePath())
    # set file extensions when offset detection is on
    if EXT:
        textext = ".text"
        jsonext = ".json"
    else:
        textext = ".exttext"
        jsonext = ".extjson"
    # Now create a file to render it to the pintool
    with open(os.path.join(path, os.path.splitext(file)[0]) + textext, "w") as f:
        count = len(metadata) - 1
        f.write("{}\n".format(count))
        for k,v in metadata.items():
            if k == ".global":
                continue
            f.write("{}\n".format(k))
            f.write("{}\n".format(v["entry"]))
            f.write("{}\n".format(v["exit"]))
            f.write("{}\n".format(v["rbp_rsp"]))
            f.write("{}\n".format(v["parameter"]))
            f.write("{}\n".format(v["stack"]))
            f.write("{}\n".format("addresses"))
            for add,val in v["addresses"].items():
                f.write("{} ".format(add))
                f.write("{} ".format(val["owner"]))
                f.write("{} ".format(val["category"]))
                f.write("{}\n".format(val["type"]))
            f.write("\n")
            f.write("{}\n".format("locals"))
            for off,var in v["variables"].items():
                f.write("{} {} {} {}\n".format(off, var["ownertype"], var["owner"], var["size"]))
            f.write("\n")
        f.write(".global\n")
        for addr,var in metadata[".global"].items():
            f.write("{} {} {} {}\n".format(str(int(addr, 16)), var["ownertype"], var["owner"], var["size"]))
        f.write("\n")

    with open(os.path.join(path, os.path.splitext(file)[0]) + jsonext, "w") as f:
        json.dump(metadata, f)

if  __name__ == '__main__':
  main()
  # print metadata
  print_metadata()
