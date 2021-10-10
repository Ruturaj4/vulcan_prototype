import sys
import re
import json
import idc
import idautils
import idaapi
import ida_struct
import ida_typeinf
import ida_frame
import ida_funcs
import ida_bytes
import ida_hexrays
import ida_nalt
# wait for auto-analysis to complete
idc.auto_wait()

# enable decompiler on objects
DECOMP = int(idc.ARGV[1])
if DECOMP:
    ida_hexrays.init_hexrays_plugin()
hexrays_types = {}
# save owner per instruction
instruction_map = {}
# global dict to store detected instructions and owners
metadata = {".global":{}}

class Instruction:
    def __init__(self, item, ea=None):
        self.item = item
        self.ea = ea
    def get_address(self):
        return format(self.item, 'x')
    def get_disassembly(self):
        return idc.GetDisasm(self.item)
    def get_operand(self, n):
        return idc.print_operand(self.item,n)
    def get_operand_type(self, n):
        return idc.get_operand_type(self.item, n)
    def get_operand_value(self, n):
        return idc.get_operand_value(self.item, n)
    def get_decoded(self):
        return idautils.DecodeInstruction(self.item)
    def get_mnemonic(self):
        return idc.print_insn_mnem(self.item)
    def get_function(self):
        return idc.get_func_name(self.item)
    def get_function_object(self):
        return ida_funcs.get_func(self.item)
    def get_inst_type(self):
        # load reg - 0
        # store imm - 1
        # store reg - 2
        if self.get_operand_type(0) == o_reg and self.get_operand_type(1) == o_reg:
            pass
        elif self.get_operand_type(0) == o_reg and self.get_operand_type(1) == o_imm:
            pass
        # load reg - 0
        elif self.get_operand_type(0) == o_reg:
            return "0"
        else:
            # store reg - 2
            if self.get_operand_type(1) == o_reg:
                return "2"
            # store imm - 1
            return "1"

class Local_variable:
    def __init__(self, mem, stack_size, ea):
        self.mem = mem
        self.stack_size = stack_size
        self.ea = ea
        self.array = False
    def get_offset(self):
        return -self.stack_size + self.mem.get_soff()
    def get_eoffset(self):
        return -self.stack_size + self.mem.eoff
    def get_size(self):
        return ida_struct.get_member_size(self.mem)
    def get_name(self):
        return idc.get_func_name(self.ea)+"_"+ida_struct.get_member_name(self.mem.id)
    # name including parent name
    def get_full_name(self):
        return ida_struct.get_member_fullname(self.mem.id)
    def get_mem(self):
        return self.mem
    def get_type(self):
        tif = ida_typeinf.tinfo_t()
        success = ida_struct.get_member_tinfo(tif, self.mem)
        return tif.get_realtype()
    def get_ownertype(self):
        tif = ida_typeinf.tinfo_t()
        success = ida_struct.get_member_tinfo(tif, self.mem)
        # guess type
        tif2 = ida_typeinf.tinfo_t()
        success2 = ida_typeinf.guess_tinfo(tif2, self.mem.id)
        # if type information is available in Ida analysis
        if success:
            if ida_typeinf.is_type_array(tif.get_realtype()):
                return "ARRAY"
            elif ida_typeinf.is_type_ptr(tif.get_realtype()):
                return "PTR"
            elif ida_typeinf.is_type_struct(tif.get_realtype()):
                return "struct"
            else:
                # return type scalar by default
                return "scalar"
        elif success2:
            if ida_typeinf.is_type_array(tif2.get_realtype()):
                return "ARRAY"
            elif ida_typeinf.is_type_ptr(tif2.get_realtype()):
                return "PTR"
            elif ida_typeinf.is_type_struct(tif.get_realtype()):
                return "struct"
            elif str(tif2) == "__int64":
                return "PTR"
            else:
                # return type scalar by default
                return "scalar"
        else:
            if self.get_size()==8:
                return "PTR"
            # elif self.get_size() not in [1,2,4,8]:
            #     return "ARRAY"
            # else:
            return "scalar"
    # without prediction
    @property
    def ownertype(self):
        tif = ida_typeinf.tinfo_t()
        success = ida_struct.get_member_tinfo(tif, self.mem)
        if success:
            if ida_typeinf.is_type_array(tif.get_realtype()):
                return "ARRAY"
            if ida_typeinf.is_type_ptr(tif.get_realtype()):
                return "PTR"
            elif ida_typeinf.is_type_struct(tif.get_realtype()):
                return "struct"
            else:
                # return type scalar by default
                return "scalar"
        return "scalar"

    def get_refs(self):
        xrefs = ida_frame.xreflist_t()
        ida_frame.build_stkvar_xrefs(xrefs, ida_funcs.get_func(self.ea), self.mem)
        return xrefs
    @property
    def is_structure(self):
        return True if ida_struct.get_sptr(self.mem) else False
    def get_struct_members(self):
        struct_members = []
        if ida_struct.get_sptr(self.mem):
            sid = ida_struct.get_sptr(self.mem).id
        else:
            return struct_members
        for mem in ida_struct.get_struc(sid).members:
            struct_members.append(Struct_members(mem, self.stack_size, self.ea))
        return struct_members

class Struct_members(Local_variable):
    def get_refs(self):
        for xref in idautils.XrefsTo(self.mem.id):
            yield(xref)
    def get_offset(self):
        return self.mem.get_soff()

# get all user defined/called functions
def get_functions():
    # functions = set()
    ignore_funs = {"__xstat", "__lxstat", "printf", ".printf", "malloc", "calloc", "realloc", "free", \
    "_init" , "puts", "__errno_location", "register_tm_clones", "__libc_csu_init", "_start", \
    "_dl_relocate_static_pie", "deregister_tm_clones", "__libc_csu_fini", "__do_global_dtors_aux",\
    ".annobin_init.c", "_fini", "frame_dummy", "fini", "entry", "start", "xcalloc", "xmalloc", "ggc_alloc", "alloc_page",\
    "xrealloc", "rtx_alloc"}
    functions = idautils.Functions()
    return [idc.get_func_name(f) for f in functions if idc.get_func_name(f) not in ignore_funs]

def predictdtype(seg_ea):
    if idc.get_item_size(seg_ea) != ida_bytes.get_data_elsize(seg_ea, idc.get_full_flags(seg_ea)):
        return "ARRAY"
    elif idc.get_item_size(seg_ea) == 8:
        return "PTR"
    else:
        return "scalar"

# get globally defined objects
def get_data_symbols(functions):
    # symbols to ignore
    ignore_symbols = {"__dso_handle", "__bss_start", "byte_404024",}
    # symbols on bss, rodata and data sections
    for seg in idautils.Segments():
        if not idc.get_segm_name(seg) in [".rodata", ".data", ".bss"]:
            continue
        for seg_ea in range(seg, idc.get_segm_end(seg)):
            if not idc.get_name(seg_ea):
                continue
            # if not idc.is_data(idc.get_full_flags(seg_ea)):
            #     continue
            if str(idc.get_name(seg_ea)) in ignore_symbols:
                continue
            if DECOMP:
                get_hexrays_vars(seg_ea)
            address = format(seg_ea, 'x')
            name = ".global_" + idc.get_name(seg_ea)
            size = idc.get_item_size(seg_ea)
            dtype = idc.guess_type(seg_ea)
            ownertype = predictdtype(seg_ea)
            obj_metadata = {"owner":name,"ownertype":ownertype, "address":address, "size":size}
            metadata[".global"][address]=obj_metadata
            if not (ownertype == "PTR" or ownertype == "ARRAY"):
                continue
            # collect references by tracing every address
            xrefs = [xref for ea in range(seg_ea, seg_ea+size) for xref in idautils.XrefsTo(ea)]
            for xref in xrefs:
                # this will ignore mov mem, imm instructions
                # print(format(xref.frm, 'x'))
                if xref.type == 1:
                    continue
                inst = Instruction(xref.frm)
                if "mov" not in inst.get_mnemonic():
                    continue
                function = inst.get_function()
                if not function:
                    continue
                adjust_off = idc.get_frame_regs_size(inst.get_function_object().start_ea)
                # print(function)
                if function not in functions:
                    continue
                # print(format(xref.frm, 'x'))
                # instrumentation category
                category = "0" if ownertype=="PTR" else "2"
                # instruction type
                itype = inst.get_inst_type()
                instruction_map[xref.frm] = name, ownertype, size, obj_metadata
                if function not in metadata:
                    metadata[function] = {"variables":{}, "addresses":{}, "entry":0, "exit":0, "stack":0, "parameter":0, "rbp_rsp":adjust_off}
                metadata[function]["addresses"][format(xref.frm, 'x')] = \
                {"owner":name, "category":category, "type":itype, "obj_metadata":obj_metadata}

def get_structure_members(function, var, offset, eoffset):
    for member in var.get_struct_members():
        owner = function+"_"+var.get_name()+"_"+member.get_name()
        offset = offset + member.get_offset()
        if offset > eoffset:
            continue
        ownertype = member.get_ownertype()
        ownertype_unpred = member.ownertype
        size = member.get_size()
        if DECOMP:
            if offset in hexrays_types[str(function)]:
                size, ownertype = hexrays_types[str(function)][offset]
                ownertype_unpred = ownertype
        if ownertype == "struct":
            get_structure_members(function, member, offset, eoffset)
        else:
            obj_metadata = {"owner":owner, "offset":offset, "ownertype":ownertype, "size":size, "ownertype_unpred":ownertype_unpred}
            metadata[function]["variables"][offset] = obj_metadata
            for xref in member.get_refs():
                # print(format(xref.frm, 'x'))
                if ida_funcs.get_func_name(xref.frm) != function:
                    continue
                inst = Instruction(xref.frm)
                instruction_map[xref.frm] = owner, ownertype, size, obj_metadata
                if "mov" not in inst.get_mnemonic():
                    continue
                # instrumentation category
                category = "0" if ownertype=="PTR" else "2"
                # instruction type
                itype = inst.get_inst_type()
                if ownertype != "scalar":
                    metadata[function]["addresses"][format(xref.frm, 'x')] = \
                    {"owner":owner, "category":category, "type":itype, "obj_metadata":obj_metadata}


def get_local_variables(ea, stack_size):
    variables = [Local_variable(mem, stack_size, ea) for mem in ida_struct.get_struc(idc.get_frame_id(ea)).members]
    function = idc.get_func_name(ea)
    for var in variables:
        # get variable name
        owner = function+"_"+var.get_name()
        # ignore special symbols
        if "_ r" in owner or "_ s" in owner:
            continue
        offset = var.get_offset()
        ownertype = var.get_ownertype()
        ownertype_unpred = var.ownertype
        size = var.get_size()
        if DECOMP:
            if offset in hexrays_types[str(function)]:
                size, ownertype = hexrays_types[str(function)][offset]
                ownertype_unpred = ownertype
        if ownertype == "struct":
            get_structure_members(function, var, offset, var.get_eoffset())
        else:
            # print(var.get_mem().eoff)
            # remove unknown arg accesses
            if not offset < 0 and var.get_mem().flag == 1024:
                continue
            # print(var.get_mem().soff)
            # print(stack_size)
            obj_metadata = {"owner":owner, "offset":offset, "ownertype":ownertype, "size":size, "ownertype_unpred":ownertype_unpred}
            metadata[function]["variables"][offset] = obj_metadata
            for xref in var.get_refs():
                # print(format(xref.ea, 'x'))
                inst = Instruction(xref.ea)
                instruction_map[xref.ea] = owner, ownertype, size, obj_metadata
                if "mov" not in inst.get_mnemonic():
                    continue
                # instrumentation category
                category = "0" if ownertype=="PTR" else "2"
                # instruction type
                itype = inst.get_inst_type()
                if ownertype != "scalar":
                    metadata[function]["addresses"][format(xref.ea, 'x')] = \
                    {"owner":owner, "category":category, "type":itype, "obj_metadata":obj_metadata}

def predict_owners(block_entry, block_exit, function, instructions):
    cur = block_entry
    # a dic of registers and pointers to be tracked
    regs={}
    while cur < block_exit:
        if not cur in instructions:
            cur+=1
            continue
        ins = instructions[cur]
        if "retn" in str(ins.get_mnemonic()):
            return
        if "leave" in str(ins.get_mnemonic()):
            return
        if "call" in str(ins.get_mnemonic()):
            regs={}
            cur+=1
            continue
        owner, ownertype, size, obj_metadata = "", "", "", ""
        if cur in instruction_map:
            owner, ownertype, size, obj_metadata = instruction_map[cur][0],\
            instruction_map[cur][1], instruction_map[cur][2], instruction_map[cur][3]
        if "mov" in str(ins.get_mnemonic()):
            if ownertype == "PTR" or ownertype == "ARRAY":
                if ins.get_operand_type(0) == o_reg and ins.get_operand_type(1) == o_reg:
                    if idaapi.get_reg_name(ins.get_operand_value(1), 8) in regs:
                        regs[idaapi.get_reg_name(ins.get_operand_value(0), 8)] = \
                        regs[idaapi.get_reg_name(ins.get_operand_value(1), 8)]
                elif ins.get_operand_type(0) == o_reg and ins.get_operand_type(1) == o_imm:
                    if idaapi.get_reg_name(ins.get_operand_value(0), 8) in regs:
                        del regs[idaapi.get_reg_name(ins.get_operand_value(0), 8)]
                elif ins.get_operand_type(0) == o_reg:
                    if ins.get_decoded().Op1.dtype != idaapi.dt_qword:
                        if idaapi.get_reg_name(ins.get_operand_value(0), 8) in regs:
                            del regs[idaapi.get_reg_name(ins.get_operand_value(0), 8)]
                    else:
                        if ownertype == "PTR":
                            regs[idaapi.get_reg_name(ins.get_operand_value(0), 8)] = owner
            else:
                if ins.get_operand_type(0) == o_reg and ins.get_operand_type(1) == o_reg:
                    if idaapi.get_reg_name(ins.get_operand_value(1), 8) in regs:
                        regs[idaapi.get_reg_name(ins.get_operand_value(0), 8)] = \
                        regs[idaapi.get_reg_name(ins.get_operand_value(1), 8)]
                elif ins.get_operand_type(0) == o_reg and ins.get_operand_type(1) == o_imm:
                    if idaapi.get_reg_name(ins.get_operand_value(0), 8) in regs:
                        del regs[idaapi.get_reg_name(ins.get_operand_value(0), 8)]
                elif ins.get_operand_type(0) == o_reg:
                    predicted = False
                    # predict owner using offset used in instruction
                    for i in [x for x in re.split('\W+', ins.get_operand(1)) if x]:
                        if i in regs:
                            # check if local pointer
                            for off,v in metadata[str(function)]["variables"].items():
                                # todo: remove this
                                if v["ownertype"] == "scalar":
                                    continue
                                if v["owner"] == regs[i]:
                                    obj_metadata = v
                                    break
                            else:
                                for addr,v in metadata[".global"].items():
                                    # todo: remove this
                                    if v["ownertype"] == "scalar":
                                        continue
                                    if v["owner"] == regs[i]:
                                        obj_metadata = v
                                        break
                            metadata[function]["addresses"][format(cur, "x")] = \
                            {"owner":regs[i], "category":"1", "type":ins.get_inst_type(), "obj_metadata":obj_metadata}
                            predicted = True
                            break
                    # unknown if this instruction is "unowned"
                    if not predicted and ownertype != "scalar":
                        metadata[function]["addresses"][format(cur, "x")] = \
                        {"owner":"unknown", "category":"4", "type":ins.get_inst_type(), "obj_metadata":"unknown"}
                    # remove the register as it may no longer contain the pointer object
                    if idaapi.get_reg_name(ins.get_operand_value(0), 8) in regs:
                        del regs[idaapi.get_reg_name(ins.get_operand_value(0), 8)]
                # mov mem, reg/imm instructions
                else:
                    predicted = False
                    # predict owner using offset used in instruction
                    for i in [x for x in re.split('\W+', ins.get_operand(0)) if x]:
                        # print(i)
                        if i in regs:
                            # check if local pointer
                            for off,v in metadata[str(function)]["variables"].items():
                                # todo: remove this
                                if v["ownertype"] == "scalar":
                                    continue
                                if v["owner"] == regs[i]:
                                    obj_metadata = v
                                    break
                            else:
                                for addr,v in metadata[".global"].items():
                                    # todo: remove this
                                    if v["ownertype"] == "scalar":
                                        continue
                                    if v["owner"] == regs[i]:
                                        obj_metadata = v
                                        break
                            metadata[function]["addresses"][format(cur, "x")] = \
                            {"owner":regs[i], "category":"1", "type":ins.get_inst_type(), "obj_metadata":obj_metadata}
                            predicted = True
                            break
                    # unknown if this instruction is "unowned"
                    if not predicted and ownertype != "scalar":
                        metadata[function]["addresses"][format(cur, "x")] = \
                        {"owner":"unknown", "category":"4", "type":ins.get_inst_type(), "obj_metadata":"unknown"}
        elif "lea" in str(ins.get_mnemonic()):
            if owner:
                if ownertype == "ARRAY":
                    regs[idaapi.get_reg_name(ins.get_operand_value(0), 8)] = owner
            else:
                # if owner is unknown then remove (as there's no other choice)
                if idaapi.get_reg_name(ins.get_operand_value(0), 8) in regs:
                    del regs[idaapi.get_reg_name(ins.get_operand_value(0), 8)]
        elif any(x in str(ins.get_mnemonic()) for x in ["add", "sub"]):
            if ins.get_operand_type(0) == o_reg and ins.get_operand_type(1) == o_reg:
                if idaapi.get_reg_name(ins.get_operand_value(1), 8) in regs:
                    regs[idaapi.get_reg_name(ins.get_operand_value(0), 8)] = \
                    regs[idaapi.get_reg_name(ins.get_operand_value(1), 8)]
        cur+=1

def predict_hexrays_type(var):
    tif = var.tif
    if ida_typeinf.is_type_array(tif.get_realtype()):
        return "ARRAY"
    elif ida_typeinf.is_type_ptr(tif.get_realtype()):
        return "PTR"
    elif ida_typeinf.is_type_struct(tif.get_realtype()):
        return "struct"
    else:
        # return type scalar by default
        return "scalar"

def get_hexrays_vars(ea, stack_size=None):
    # print(str(ida_hexrays.decompile(ea)).strip())
    hexrays_types[idc.get_func_name(ea)] = {}
    try:
        decompiled = ida_hexrays.decompile(ea)
    except ida_hexrays.DecompilationFailure:
        return
    if not decompiled:
        return
    for var in ida_hexrays.decompile(ea).get_lvars():
        if not var.name:
            continue
        # print(var.width)
        offset = -stack_size + var.get_stkoff()
        ownertype = predict_hexrays_type(var)
        hexrays_types[idc.get_func_name(ea)][offset] = var.width, ownertype

def function_iterator(functions):
    for ea in idautils.Functions():
        if not idc.get_func_name(ea) in functions:
            continue
        if idc.get_frame_id(ea) == None:
            continue
        if not idc.get_segm_name(ea) == ".text":
            continue
        # check if library function
        if idc.get_func_flags(ea) & FUNC_LIB:
            continue
        # function name
        function = idc.get_func_name(ea)
        if DECOMP:
            get_hexrays_vars(ea, idc.get_func_attr(ea, idc.FUNCATTR_FRSIZE))
        print(function)
        # function stack size
        stack_size = idc.get_func_attr(ea, idc.FUNCATTR_FRSIZE)
        parameter_size = max([-stack_size + mem.eoff for mem in ida_struct.get_struc(idc.get_frame_id(ea)).members if not mem.flag == 1024]+[8])
        adjust_off = idc.get_frame_regs_size(ea)
        # print(idc.get_frame_lvar_size(ea))
        # print(idc.get_frame_args_size(ea))
        # print(idc.get_frame_size(ea))
        # stack_size = idc.get_frame_size(ea)
        # print(stack_size)
        # function boundary
        fun_entry = format(idc.get_func_attr(ea, FUNCATTR_START), 'x')
        fun_exit = format(idc.get_func_attr(ea, FUNCATTR_END)-1, 'x')
        # instructions
        instructions = {item:Instruction(item, ea) for item in idautils.FuncItems(ea)}
        if function in metadata:
            metadata[str(function)]["entry"] = fun_entry
            metadata[str(function)]["exit"] = fun_exit
            metadata[str(function)]["parameter"] = str(parameter_size)
            metadata[str(function)]["stack"] = str(stack_size)
            metadata[str(function)]["rbp_rsp"] = str(adjust_off)
        else:
            metadata[str(function)] = {"variables":{}, "addresses":{}, "parameter":parameter_size, "rbp_rsp":str(adjust_off), "stack":stack_size, \
            "entry":fun_entry, "exit":fun_exit}
        # get function local variables
        get_local_variables(ea, stack_size)
        # iterate through static building blocks
        flowchart = idaapi.FlowChart(idaapi.get_func(ea))
        for bb in flowchart:
            predict_owners(bb.start_ea ,bb.end_ea, function, instructions)

def print_metadata():
    path, file = os.path.split(ida_nalt.get_input_file_path())
    # Now create a file to render it to the pintool
    with open(os.path.join(path, os.path.splitext(file)[0]) + ".idatext", "w") as f:
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
                f.write("{} {} {} {}\n".format(add, val["owner"], val["category"], val["type"]))
            f.write("\n")
            f.write("{}\n".format("locals"))
            for off,var in v["variables"].items():
                f.write("{} {} {} {}\n".format(off, var["ownertype"], var["owner"], var["size"]))
            f.write("\n")
        f.write(".global\n")
        for add,var in metadata[".global"].items():
            f.write("{} {} {} {}\n".format(str(int(add, 16)), var["ownertype"], var["owner"], var["size"]))
        f.write("\n")

    with open(os.path.join(path, os.path.splitext(file)[0]) + ".idajson", "w") as f:
        json.dump(metadata, f)

def main():
    # ida automatically "find's" main
    # api endpoint is available to get basic blocks
    # get functions
    # get all user defined/called functions
    functions = get_functions()
    # get globally defined objects
    get_data_symbols(functions)
    # iterate through functions
    function_iterator(functions)

if  __name__ == '__main__':
  main()
  # print metadata
  print_metadata()

idc.qexit(0)
