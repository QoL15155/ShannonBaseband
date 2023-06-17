import ida_struct
import ida_ida
import idc
import idaapi
import logging
import sys
import ida_bytes
import idautils

#
# Loggers Configuration
###


def configLogger(name, level):
    logger = logging.getLogger(name)
    if len(logger.handlers) != 0:
        print(f"[configLogger] Logger {name} already have handlers")
        return logger
    logger.setLevel(level)
    LOG_FORMAT = "[%(levelname)s] [%(name)s.%(funcName)s] %(message)s"
    formatter = logging.Formatter(LOG_FORMAT)
    mainStream = logging.StreamHandler(sys.stdout)
    mainStream.setFormatter(formatter)
    logger.addHandler(mainStream)
    return logger

#
# Struct Utils
#


def get_struct(name):
    fname = "get_struct"
    sid = ida_struct.get_struc_id(name)
    if sid == idc.BADADDR:
        print(f"[ERROR] [{fname}] Structure {name} doesn't exist!")
        return idc.BADADDR
    return ida_struct.get_struc(sid)


def enum_struct_members(st):
    idx = 0
    while idx != -1:
        member = st.get_member(idx)
        yield member
        idx = idaapi.get_next_member_idx(st, member.soff)


""" 
Prints out the structure's member types.
Assumes structure exists
"""


def dump_struct_schema(name):
    fname = "check_struct_types"
    st = get_struct(name)
    if st == idc.BADADDR:
        print(f"Structure {name} doesn't exist!")
        return
    # Enumerate struct members
    # TODO: either remove or at least get in logger.deubg
    print(f"[{fname}] Enumerating members of {name}")
    for mem in enum_struct_members(st):
        name = ida_struct.get_member_name(mem.id)
        print(f"Name: {name}, Flag: {hex(mem.flag)}")


def add_structure(name):
    sid = ida_struct.get_struc_id(name)
    if sid != idc.BADADDR:
        # logger.info(f"struct {name} already exists. id: {sid}")
        idc.del_struc(sid)

    sid = idc.add_struc(-1, name, 0)
    # add_struct_to_idb(name)
    return sid

# TODO: what is this???
# def add_struct_to_idb(name):
    # idc.import_type(-1, name)

#
# Pointer Games
#


def get_string(ea):
    b = ida_bytes.get_strlit_contents(ea, -1, idc.STRTYPE_C)
    return b.decode() if b else None


def search_string(phrase):
    """ Searches for @param phrase in the entire idb """
    pattern = ida_bytes.compiled_binpat_vec_t()
    start_ea = ida_ida.inf_get_min_ea()
    end_ea = ida_ida.inf_get_max_ea()
    # flags = ida_bytes.BIN_SEARCH_FORWARD
    flags = ida_bytes.BIN_SEARCH_CASE
    ea = start_ea
    ida_bytes.parse_binpat_str(pattern, start_ea, phrase, 10)
    while (ea < end_ea):
        ea = ida_bytes.bin_search(ea, end_ea, pattern, flags)
        if ea == idaapi.BADADDR:
            break
        yield ea
        ea += 1

#
# Misc
#

# TODO: see if this actually needed


def list_segments():
    print("Listing Segments")
    for s in idautils.Segments():
        start = idc.get_segm_start(s)
        end = idc.get_segm_end(s)
        name = idc.get_segm_name(s)
        data = ida_bytes.get_bytes(start, end-start)
        print(f"[{name}] Start:{start}, End:{end}")
