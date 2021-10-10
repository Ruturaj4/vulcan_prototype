import os
import sys
import json
from collections import Counter
import pandas as pd
from functools import reduce
# to work with dwarf
import elftools
from elftools.elf.elffile import ELFFile
from elftools.dwarf.descriptions import describe_attr_value

# global dictionary to store type information per function per program
global_dic = {"functions":{}, ".global":{"pointers":[],"arrays":[]}}
# global dictionary to store stucture information and direct member offsets globally
struct_dic = {}

# ignore variables
ignore_variables = {"stdin", "stdout", "stderr", "sys_errlist", "sys_nerr", "__PRETTY_FUNCTION__",\
"_sys_siglist","sys_siglist", "__environ", "optarg"}

def leb128_decode(num):
    result = shift = size = 0
    for byte in [int(hex(i), 16) for i in num]:
        result |= (byte & 0x7f) << shift
        shift += 7
        # sign bit of byte is second high order bit (0x40)
        if byte & 0x80 == 0:
            break
    if byte & 0x40:
        # sign extend
        result -= (1 << shift);
    return result

def parse_location(location):
    if not isinstance(location, list):
        return "unknown", "unknown"
    if location[0] == 145:
        return "local", leb128_decode(location[1:])
    # todo: implement decoding algorithm in future
    elif location[0] == 3:
        return  "static", "unknown"
    else:
        return "unknown","unknown"

def parse_pointer(DIE):
    return DIE.attributes["DW_AT_byte_size"].value

def parse_array_type(DIE):
    # if type is volatile then go 1 level deeper
    if DIE.tag in ["DW_TAG_volatile_type", "DW_TAG_const_type", "DW_TAG_typedef"]:
        return parse_array_type(DIE.dwarfinfo.get_DIE_from_refaddr(DIE.attributes["DW_AT_type"].value+DIE.cu.cu_offset))
    else:
        return DIE.attributes["DW_AT_byte_size"].value

def parse_array(DIE):
    # find array size through his sibling
    # it is possible that an array is multidimensional
    arraysize = []
    for childrendie in DIE.iter_children():
        if "DW_AT_upper_bound" not in childrendie.attributes:
            return "unknown"
        if isinstance(childrendie.attributes["DW_AT_upper_bound"].value, list):
            return "unknown"
        arraysize.append(childrendie.attributes["DW_AT_upper_bound"].value+1)
    # find array type
    typedie = DIE.dwarfinfo.get_DIE_from_refaddr(DIE.attributes["DW_AT_type"].value+DIE.cu.cu_offset)
    byte_size = parse_array_type(typedie)
    # update byte size in to calculate the total size of an object
    arraysize.append(byte_size)
    # return calculated size - after multiplying all elements of an array
    return reduce(lambda x,y: x*y, arraysize)

def parse_struct(function, parent_offset, attribute):
    for vartype,value in struct_dic[attribute].items():
        if vartype == "pointers":
            for pointer in value:
                offset, name, attribute = pointer
                global_dic["functions"][function]["pointers"].append([parent_offset+offset, name, attribute])
        elif vartype == "arrays":
            for array in value:
                offset, name, attribute = array
                global_dic["functions"][function]["arrays"].append([parent_offset+offset, name, attribute])
        elif vartype == "nodes":
            for node in value:
                offset, name = node
                parse_struct(function, parent_offset+offset, name)

# type excavation
def die_recursive(DIE):
    if "DW_AT_type" in DIE.attributes:
        typedie = DIE.dwarfinfo.get_DIE_from_refaddr(DIE.attributes["DW_AT_type"].value+DIE.cu.cu_offset)
    else:
        return "unknown","unknown"
    # print(typedie)
    if typedie.tag == "DW_TAG_pointer_type":
        return "pointer", parse_pointer(typedie)
    if typedie.tag == "DW_TAG_array_type":
        return "array", parse_array(typedie)
    if typedie.tag == "DW_TAG_structure_type":
        # return structure name instead of size
        if "DW_AT_name" in typedie.attributes:
            return "struct", typedie.attributes["DW_AT_name"].value.decode("utf-8")
        else:
            return "unknown","unknown"
    else:
        return die_recursive(typedie)
    return "unknown","unknown"

def detect_structs(structure, DIES):
    for DIE in DIES:
        if not DIE.tag == "DW_TAG_member":
            continue
        name = DIE.attributes["DW_AT_name"].value.decode("utf-8")
        offset = DIE.attributes["DW_AT_data_member_location"].value
        vartype, attribute = die_recursive(DIE)
        if attribute == "unknown":
            continue
        if vartype == "pointer":
            struct_dic[structure]["pointers"].append([offset, name, attribute])
        elif vartype == "array":
            struct_dic[structure]["arrays"].append([offset, name, attribute])
        elif vartype == "struct":
            struct_dic[structure]["nodes"].append([offset, attribute])

def detect_locals(function, DIES):
    for DIE in DIES:
        if DIE.tag == "DW_TAG_variable" or DIE.tag == "DW_TAG_formal_parameter":
            # if "DW_AT_location" in DIE.attributes:
            #     print(describe_attr_value(DIE.attributes["DW_AT_location"], DIE, DIE.cu.cu_offset))
            if not "DW_AT_name" in DIE.attributes:
                continue
            # this will ignore non stack variables
            if not "DW_AT_location" in DIE.attributes:
                continue
            name = DIE.attributes["DW_AT_name"].value.decode("utf-8")
            if name in ignore_variables:
                continue
            position, offset = parse_location(DIE.attributes["DW_AT_location"].value)
            # continue if position is not respect to 0x91
            if position == "unknown" or position == "static":
                continue
            # adjust the offset
            offset += 8
            vartype, attribute = die_recursive(DIE)
            if vartype == "pointer":
                global_dic["functions"][function]["pointers"].append([offset, name, attribute])
            if vartype == "array":
                global_dic["functions"][function]["arrays"].append([offset, name, attribute])
            if vartype == "struct":
                parse_struct(function, offset, attribute)
        elif DIE.tag == "DW_TAG_lexical_block":
            if DIE.has_children:
                detect_locals(function, DIE.iter_children())

def detect_globals(CU):
    # collect all dies for type detection
    for DIE in CU.iter_DIEs():
        # check if the variable is global
        if DIE.tag == "DW_TAG_variable" and "DW_AT_name" in DIE.attributes:
            if DIE.get_parent().tag == "DW_TAG_compile_unit":
                name = DIE.attributes["DW_AT_name"].value.decode("utf-8")
                if name in ignore_variables:
                    continue
                # print(name)
                typedie = die_recursive(DIE)
                if typedie == "pointer":
                    global_dic[".global"]["pointers"].append(name)
                if typedie == "array":
                    global_dic[".global"]["arrays"].append(name)
        if DIE.tag == "DW_TAG_structure_type":
            if not "DW_AT_name" in DIE.attributes:
                continue
            structure = DIE.attributes["DW_AT_name"].value.decode("utf-8")
            struct_dic[structure] = {"pointers":[],"arrays":[], "nodes":[]}
            # this will extract all global structures and corresponding nodes
            # to find nested structures
            detect_structs(structure, DIE.iter_children())
        if DIE.tag == "DW_TAG_subprogram":
            if not "DW_AT_name" in DIE.attributes:
                continue
            if not "DW_AT_low_pc" in DIE.attributes:
                continue
            if not DIE.has_children:
                continue
            # function = DIE.attributes["DW_AT_name"].value.decode("utf-8")
            # store function metadata according to function prologue
            function = DIE.attributes["DW_AT_low_pc"].value
            global_dic["functions"][function] = {"pointers":[],"arrays":[],"variables":[]}
            detect_locals(function, DIE.iter_children())

def main():
    # take filepath
    filepath = sys.argv[1]
    # open file and seek elffile object
    with open(filepath, "rb") as f:
        elffile = ELFFile(f)
        # extract the dwarf symbol information
        dwarfinfo = elffile.get_dwarf_info()
        # get disassembly
        code = elffile.get_section_by_name(".text")
        # print(dir(dwarfinfo))
        for CU in dwarfinfo.iter_CUs():
            detect_globals(CU)
    # print(global_dic)
    # print(struct_dic)
    with open(os.path.splitext(filepath)[0] + ".typejson", "w") as f:
        json.dump(global_dic, f)

if  __name__ == '__main__':
  main()
