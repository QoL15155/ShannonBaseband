import ida_struct
import ida_lines
import ida_bytes
import ida_name
import idc
import ida_ida
import ida_entry
import idautils
import idaapi
import ida_segment
import ida_idp
import struct
import ida_kernwin
import logging
import modem_utils as utils
import modem_debug_msg as modem_dbg
import vector_table

logger = utils.configLogger("Modem_Loader", logging.DEBUG)

STRUCT_TOC_ENTRY = "st_radio_entry"

# 
# Starts of Code
# 

class RadioEntry(object):
	def __init__(self, name, ea):
		self.__name = name
		self.__offset = ea + 0xc
		self.__load_address = ea + 0x10
		self.__size = ea + 0x14
		self.__crc = ea + 0x18
		self.__section_id = ea + 0x1c
		
	def get_entry_name(fd):
		try:
			name = struct.unpack("<12s", fd.read(12))[0]
			return name.decode().strip("\x00")
		except UnicodeDecodeError:
			return None
	
	def __init__(self, fd):
		self.__name = RadioEntry.get_entry_name(fd)
		entry_bytes = fd.read(4 * 5)
		self.__offset, self.__load_address, self.__size, self.__crc, self.__section_id = struct.unpack("<IIIII", entry_bytes)
	
	def __str__(self):
		return f"[{self.name}] off={hex(self.offset)}, sz={self.size}, load_address={hex(self.load_address)}"

	@property
	def name(self):
		return self.__name

	@property
	def load_address(self):
		return self.__load_address

	@property
	def unload_address(self):
		return self.__load_address + self.__size
	
	@property
	def offset(self):
		return self.__offset

	@property
	def size(self):
		return self.__size
	

# 
# Segment Parsing
#

def try_parse_header(fd, entries):
	""" Tried to add entry into dictionary """
	entry = RadioEntry(fd)
	name = entry.name
	if not name:
		return False
	if name in entries:  # Sanity test. Shouldn't happen	
		logger.error(f"TOC headers contains a duplicate section name: '{name}'")
		return False

	entries[name] = entry
	logger.debug(f"{entry}")
	return True

def try_parse_headers(fd):
	""" Parses headers into entries dictionary.
		Assumes the first header is TOC entry
		Returns: True when structure is valid
	"""
	radio_entries = {}  # name / values
	fd.seek(0)
	while True:
		if not try_parse_header(fd, radio_entries):
			logger.info(f"Finished parsing TOC entries. {len(radio_entries)}")
			break

	# Verify Entries
	if "BOOT" not in radio_entries or "MAIN" not in  radio_entries:
		idaapi.error(f"Missing crucial entries in order to parse Radio image")
		return None
	return radio_entries


def apply_segments(fd, radio_entries):
	for entry in radio_entries.values():
		fd.file2base(entry.offset, entry.load_address, entry.unload_address, True)
		if entry.name == "BOOT" or entry.name == "MAIN":
			flag = "CODE"
		else:
			flag = "DATA"
		idaapi.add_segm(0, entry.load_address, entry.unload_address, entry.name, flag)
		match entry.name:
			case "TOC":
				ida_lines.add_extra_line(entry.load_address, True, "Table of Contents")
			case "BOOT":
				ida_lines.add_extra_line(entry.load_address, True, "Baseband bootstrap code")
			case "MAIN":
				ida_lines.add_extra_line(entry.load_address, True, "Shannon Modem baseband")
				# Add entry point
				# ida_entry.add_entry(entry.load_address, entry.load_address, "start", 1)
			case "NV":
				ida_lines.add_extra_line(entry.load_address, True, "Non-volatile memory")

#
# Segment TOC
#

def create_toc_entry_struct():	
	""" Create toc entry struct in idb """
	sid = utils.add_structure(STRUCT_TOC_ENTRY)
	idc.add_struc_member(sid, "name", 0x0, ida_bytes.FF_STRLIT, -1, 12);
	idc.add_struc_member(sid, "offset", -1, ida_bytes.FF_DWORD, -1, 4);
	idc.add_struc_member(sid, "load_address", -1, ida_bytes.FF_DWORD, -1, 4);
	idc.add_struc_member(sid, "size", -1, ida_bytes.FF_DWORD, -1, 4);
	idc.add_struc_member(sid, "crc", -1, ida_bytes.FF_DWORD, -1, 4);
	idc.add_struc_member(sid, "id", -1, ida_bytes.FF_DWORD, -1, 4);
	return sid

def try_parse_seg_toc_entry(ea, sz, first_entry):
	""" Tries to parse TOC entry in idb """
	name = utils.get_string(ea)
	# Sanity checks
	if not name: 
		return False
	if first_entry and name != "TOC":
		logger.error(f"Unexpected image. Doesn't start with TOC entry. offset={hex(ea)}. Name={name}")
		return False
	if not idc.create_struct(ea, sz, STRUCT_TOC_ENTRY):
		logger.error(f"Failed to create struct {STRUCT_TOC_ENTRY} at addr {hex(ea)}")
		return False
		
	ida_name.set_name(ea, f"entry_{name.lower()}", ida_name.SN_PUBLIC)  # Variable
	logger.debug(f"{hex(ea)} - {name}")
	# Set Comment
	if name == "TOC":
		ida_lines.add_extra_cmt(ea, True, "Table Of Contents")
	elif name == "BOOT":
		ida_lines.add_extra_cmt(ea, True, "Baseband bootstrap code")
	elif name == "MAIN":
		ida_lines.add_extra_cmt(ea, True, "Baseband code")
	elif name == "NV":
		ida_lines.add_extra_cmt(ea, True, "Non-volatile memory")
		ida_lines.add_extra_cmt(ea, True, "Likely baseband settings or something")

	return True


def parse_TOC_segment(toc_addr):
	sid = create_toc_entry_struct()
	sz_struct = ida_struct.get_struc_size(sid)

	# Apply TOC entry structs
	first_entry = True
	offset = toc_addr
	while True:
		if not try_parse_seg_toc_entry(offset, sz_struct, first_entry):
			logger.info(f"Finished parsing TOC entries. {hex(offset)}")
			return
		first_entry = False
		offset += sz_struct

#
# Loader
# https://www.hex-rays.com/products/ida/support/sdkdoc/structloader__t.html
#
# Loader Example: https://github.com/ocean1/reversing_stuff/blob/master/3dsx.py
#

def accept_file(fd, pathname):
	TOC_MAGIC = "TOC" 
	fd.seek(0)
	if RadioEntry.get_entry_name(fd) != TOC_MAGIC:
		return 0
	# entries = try_parse_entries()	
	# return 0 if entries is None else f"Radio Modem Image"
	return {"format": f"Radio Modem Image", "processor": "arm"}

def load_file(fd, neflags, format):
	idaapi.set_processor_type("arm", ida_idp.SETPROC_LOADER)

	# This boolean will be set if IDA is "reloading" the file as opposed to 
	# loading it for the first time, i.e., File->Load File->Reload Input File.
	# We just ignore requests to reload.
	if (neflags & idaapi.NEF_RELOAD) != 0:
		return 1

	dict_radio_entries = try_parse_headers(fd)	
	if not dict_radio_entries:
		logger.error("Failed to get entries")
		return 0

	logger.info(f"Applying Segments")
	apply_segments(fd, dict_radio_entries)
	# TODO: apply permissions?
	parse_TOC_segment(dict_radio_entries["TOC"].load_address)
	vector_table.parse(dict_radio_entries["BOOT"].load_address, "boot")
	vector_table.parse(dict_radio_entries["MAIN"].load_address, "main")
	if ida_kernwin.ask_yn(0, 'Add Debug struct?'):
		modem_dbg.parse()

	return 1
