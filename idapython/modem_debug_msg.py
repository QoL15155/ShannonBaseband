import idaapi
import idc
import ida_struct
import ida_bytes
import ida_lines
import ida_ida
import logging
import modem_utils as utils

logger = utils.configLogger("Segment_Main", logging.DEBUG)

# Constants
STRUCT_MSG_DBG = "st_DebugMsg"

# 
# Structure for Debugging messages
#

def find_or_create_dbg_msg_struct():
	sid = utils.add_structure(STRUCT_MSG_DBG)
	st = ida_struct.get_struc(sid)
	if not st:
		logger.error(f"Failed to get structure. sid: {sid}")
		return
	mid = idc.add_struc_member(sid, "magic", 0x0, idaapi.FF_STRLIT, -1, 4);
	ida_struct.set_member_cmt(st.get_member(mid), "Magic number", True)

	idc.add_struc_member(sid, "num1", 0x4, idaapi.FF_DWORD, -1, 4);
	idc.add_struc_member(sid, "num2", 0x8, idaapi.FF_DWORD, -1, 4);
	idc.add_struc_member(sid, "num3", 0xc, idaapi.FF_DWORD, -1, 4);
	idc.add_struc_member(sid, "msg", 0x10, idaapi.FF_DWORD | idaapi.FF_1OFF | idaapi.FF_0OFF, -1, 4);
	idc.add_struc_member(sid, "line_number", 0x14, idaapi.FF_DWORD, -1, 4);
	idc.add_struc_member(sid, "source_file", 0x18, idaapi.FF_DWORD | idaapi.FF_1OFF | idaapi.FF_0OFF, -1, 4);
	return sid

# TODO: put in utils. is name good?
def parse_string_from_ptr(ea):
	ptr = idc.get_wide_dword(ea)
	s = utils.get_string(ptr)	
	if s != None:
		idc.create_strlit(ptr, ptr + len(s))
		# TODO: add xrefs to ea?
		# ida_name.set_name(ptr, "dbg")

	return s

def define_dbg_structs():
	HEX_MAGIC = "44 42 54 3a"  # "DBT:"
	dbg_pattern = ida_bytes.compiled_binpat_vec_t()
	start_ea = ida_ida.inf_get_min_ea()
	end_ea = ida_ida.inf_get_max_ea()
	flags = ida_bytes.BIN_SEARCH_FORWARD
	ea = start_ea
	count_st = 0
	count_failed_st = 0
	ida_bytes.parse_binpat_str(dbg_pattern, start_ea, HEX_MAGIC, 16)
	logger.info(f"start_ea = {hex(ea)}, end_ea = {hex(end_ea)}")
	while (ea < end_ea):
		ea = ida_bytes.bin_search(ea, end_ea, dbg_pattern, flags)
		if ea == idaapi.BADADDR: 
			break 
		count_st += 1
		dbg_msg = parse_string_from_ptr(ea+0x10)
		# if not dbg_msg:
		# 	logger.warning(f"No dbg msg. Failed to create dbg_struct at: {hex(ea)}")
		# 	count_failed_st += 1
		# 	ea += 4
		# 	continue
		line_num = idc.get_wide_dword(ea+0x14)
		source_file = parse_string_from_ptr(ea+0x18)
		if not source_file:
			logger.warning(f"No source file. Failed to create dbg_struct at: {hex(ea)}")
			count_failed_st += 1
			ea += 4
			continue
		idc.create_struct(ea, -1, STRUCT_MSG_DBG)
		# ida_lines.delete_extra_cmts(ea, ida_lines.E_PREV)
		ida_lines.add_extra_cmt(ea, True, f"Message: {dbg_msg}")
		ida_lines.add_extra_cmt(ea, True, f"SourceFile: \"{source_file}\"\t(line {line_num})")
		ea += 4
		# name = idc.get_name(ea + 0x10)
	logger.info(f"Finished. Dbg messages: {count_st}. Fails:{count_failed_st}")

def parse():
	logger.info("Parsing Debug struct")
	# TODO: check segments (only in main?)
	sid = find_or_create_dbg_msg_struct()
	utils.check_struct_types(STRUCT_MSG_DBG)
	define_dbg_structs()
