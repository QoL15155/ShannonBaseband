import ida_bytes
import idaapi
import ida_ida
import modem_utils as utils
import idautils
import idc


def func_basic_blocks(addr):
    func = idaapi.get_func(addr)
    if not func:
        print(f"Not a function: {hex(addr)}")
        return
    flow_chart = idaapi.FlowChart(func)
    print(
        f"Function '{idaapi.get_func_name(addr)}'. Flow Chart: {flow_chart.size}")


def search_shannon_os_version():
    SHANNON_OS = '"_ShannonOS"'
    # SHANNON_OS = '"ShannonOS"'
    shannon_versions = []
    print(f"Looking for {SHANNON_OS}")
    for ptr in utils.search_string(SHANNON_OS):
        version = utils.get_string(ptr)
        shannon_versions.append((ptr, version))
        print(f"Found: {hex(ptr)} - {version}")
        # Create string
        idc.create_strlit(ptr, idc.BADADDR)
    if len(shannon_versions) != 1:
        print("Too many options for Shannon OS Version")
        return shannon_versions

    # Found variable - rename it
    ptr = shannon_versions[0][0]
    idc.set_name(ptr, "shannon_os_version", SN_CHECK)
    # Find xrefs to this variable
    xrefs = idautils.XrefsTo(ptr)
    for xref in xrefs:
        t = idautils.XrefTypeName(xref.type)
        func = idaapi.get_func(xref.frm)
        print(f"> Type:{t}, from: {hex(xref.frm)}, To:{hex(xref.to)}")
        # print(f"Code?{ida_bytes.is_code(xref.frm)}, Data? {ida_bytes.is_data(xref.frm)}, flags:{ida_bytes.get_flags(xref.frm)}")
        if not func:
            continue
        print(f"Function {idaapi.get_func_name(xref.frm)}: {func}")
        flow_chart = idaapi.FlowChart(func)
        print(f"Flow Chart: {flow_chart.size}")

        # print(f"Type:{xref.type}, from: {hex(xref.frm)}, To:{hex(xref.to)}")


def find_mpu_table():
    Base_Address = "00 00 00 00 00 00 00 00"
    Size_Code = "1c 00 00 00 00"
    pattern = "00 00 00 00 00 00 00 00 1c 00 00 00 00"


def parse():
    search_shannon_os_version()
    func_basic_blocks(0x417FD31c)


parse()
