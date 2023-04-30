import ida_struct
import idc
import idaapi
import logging
import sys

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
Prints out the structure's types.
Assumes structure exists
"""
def check_struct_types(name):
	fname = "check_struct_types"
	st = get_struct(name)
	if st == idc.BADADDR:
		print(f"Structure {name} doesn't exist!")
		return
	# Enumerate struct members
	print(f"[{fname}] Enumerating members of {name}")
	for mem in enum_struct_members(st):
		name = ida_struct.get_member_name(mem.id)
		print(f"Name: {name}, Flag: {hex(mem.flag)}")
		