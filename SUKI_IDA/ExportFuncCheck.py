import ida_entry
import ida_funcs
import idaapi
import idc


def get_export_functions():
    exports = []
    export_count = ida_entry.get_entry_qty()

    for i in range(export_count):
        ordinal = ida_entry.get_entry_ordinal(i)
        ea = ida_entry.get_entry(ordinal)
        if ea != idaapi.BADADDR:
            func = ida_funcs.get_func(ea)
            if func:
                func_size = func.end_ea - func.start_ea 
            else:
                func_size = -1  
            
            exports.append((ordinal, ea, func_size))

    return exports

class export_func_check(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)
    
    def activate(self, ctx):
        export_funcs = get_export_functions()
        for ordinal, addr, size in export_funcs:
            if ordinal == addr:
                print(f"[EFC] Ordinal: unknown, Address: {hex(addr)}, Size: {size} bytes")
            else:
                print(f"[EFC] Ordinal: {ordinal}, Address: {hex(addr)}, Size: {size} bytes")

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS



