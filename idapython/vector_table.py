import ida_bytes
import ida_name
import idc
import idautils
import ida_funcs
import logging
import modem_utils as utils

logger = utils.configLogger("Vector_Table", logging.DEBUG)

""" Assumes Cortex-R7 vector table """
vector_table = ["Reset", "Undefined", "software_interrupt", "prefetch_abort", "data_abort", "not_used", "irq", "fiq"]

def get_function(ea): 
    it = idautils.CodeRefsFrom(ea, 0)
    s = set(it)
    if (len(s)!=1):
        logger.warning(f"Failed to get function at {hex(ea)}")
        return None
    return s.pop()
     
def check_entry(ea):
    """ Checks the entry is valid """
    cmd = ida_bytes.get_word(ea+2)
    if cmd == 0xe59f:  # LDR PC, =loc_xxxxxx
        return True
    cmd = ida_bytes.get_byte(ea+3)
    return cmd == 0xea  # b sub_44B4

def parse(ea, segname):
    logger.info(f"Parsing Vector Table for {segname}")
    ea -= 4
    for idx in range(len(vector_table)):
        ea += 4
        if not check_entry(ea):
            logger.warning(f"Unexpected command at {hex(ea)}")
            continue
        ida_name.set_name(ea, f"{segname}_{vector_table[idx]}", idc.SN_NOCHECK)
        if idc.create_insn(ea) != 4:
            logger.warning(f"Failed to create instruction at {hex(ea)}")
            continue 
        ptr_func = get_function(ea)
        if not ptr_func:
            logger.warning(f"Failed to get function pointer at {hex(ea)}")
            continue
        ida_funcs.add_func(ptr_func)
        ida_name.set_name(ptr_func, f"{segname}_{vector_table[idx]}_handler")
