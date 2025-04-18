import idaapi
import idc
import ida_hexrays
import ida_funcs
import ida_bytes
import ida_frame
import ida_dbg
import ida_lines
import ida_idaapi
import ida_segment
import ida_gdl
import ida_ida


# reg for x86
reg_list = [
    'EAX', 'EBX', 'ECX', 'EDX', 'ESI', 'EDI', 'EBP', 'ESP',  
    'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp',  
    'AX', 'BX', 'CX', 'DX', 'SI', 'DI', 'BP', 'SP', 
    'ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp',  
    'AL', 'AH', 'BL', 'BH', 'CL', 'CH', 'DL', 'DH', 
    'al', 'ah', 'bl', 'bh', 'cl', 'ch', 'dl', 'dh',  
  
]

# reg for x64
reg64 = [
    'RAX', 'RBX', 'RCX', 'RDX', 'RSI', 'RDI', 'RBP', 'RSP', 
    'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',  
    'R8', 'R9', 'R10', 'R11', 'R12', 'R13', 'R14', 'R15',    
    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',   
]

# end flag for security cookie finder
compare = ['test', 'cmp']

# info make
byte_wide = 0
is_64bit = ida_ida.inf_is_64bit()
if is_64bit:
    byte_wide = 8
    reg_list += reg64
else:
    byte_wide = 4


# get memory value
def get_value(point):
    # point: memory address

    if byte_wide == 4:
        return ida_bytes.get_dword(point)

    elif byte_wide == 8:
        return ida_bytes.get_qword(point)


class DVC:
    def __init__(self):
        self.here_addr = ida_dbg.get_ip_val()
        self.here_sp = ida_dbg.get_sp_val()
        self.func = ida_funcs.get_func(self.here_addr)
        self.func_start = self.func.start_ea
        self.func_end = self.func.end_ea
        self.c_func = ida_hexrays.decompile(self.here_addr)
        self.block_var = []
        self.vars_name = []
        self.block_check = False
        self.first_block_end = 0

    def DVC(self):
        lvars = self.c_func.get_lvars()
        spd = ida_frame.get_spd(self.func, self.here_addr)
        point = self.func_start        

        # check security cookie is exist
        while point <= self.first_block_end and point <= self.func_end:
            disasm = idc.GetDisasm(point)
            if any([compare_word in disasm for compare_word in compare]):
                break
            if 'security_cookie' in disasm:
                spd += byte_wide
                print(f'[DVC] security_cookie found at {hex(point)}')
                break
            point = idc.next_head(point)

        # get current block var name list
        self.vars_name = [var.name for var in lvars if var.name != '']
        if self.set_block_var() != True:
            print('[DVC] set block var fail')
            return

        # check local var
        for var in lvars:
            if var.name == '':
                continue
            if self.block_check == True and var.name not in self.block_var:
                continue
            if var.is_reg1():
                reg = var.get_reg1()
                reg_name = ida_hexrays.get_mreg_name(reg, var.width)
                if reg_name in reg_list:
                    reg_value = idc.get_reg_value(reg_name)
                    self.rename(reg_value, var)
                else:
                    print(f'[DVC] unknown register {var.name}: {reg_name}')
            elif var.is_stk_var():
                stk_var_address = self.here_sp - (spd + (self.func.frsize - (var.get_stkoff() - self.c_func.get_stkoff_delta())))
                stk_var_value = get_value(stk_var_address)
                self.rename(stk_var_value, var)
            else:
                print(f'[DVC] something is wrong in {var.name}')
                continue

    # reuname local var
    def rename(self, var_value, var):

        func_name = self.get_name(var_value)
        ret = True
        name_count = 1
        if func_name != None:
            ret = ida_hexrays.rename_lvar(self.func_start, var.name, func_name)
            func_name = func_name + '_'
            while ret == False:
                if name_count >=20:
                    print(f"[DVC] rename fail, try {var.name} rename to {func_name + str(name_count)}")
                    break
                
                ret = ida_hexrays.rename_lvar(self.func_start, var.name, func_name + str(name_count))
                name_count += 1
            print(f'[DVC] {var.name} rename to {func_name + str(name_count-1)}')

    
    # as long as one of the three levels below the variable has a symbol，return there name, rename this variable
    def get_name(self, point):
        # point: var_value
        next_point = point
        count = 0
        flag = False
        while count <= 3:
            try:
                if not idc.is_mapped(next_point):
                        break
            except TypeError:
                break

            # dll handle check
            seg = ida_segment.getseg(point)
            seg_name = ida_segment.get_segm_name(seg)
            if seg and ('dll' in seg_name or 'DLL' in seg_name) and point == seg.start_ea:
                return seg_name.replace('.','_')

            # symbol check
            flag = ida_funcs.add_func(point)
            symbol_name = idc.get_name(point, idc.GN_VISIBLE)
            if symbol_name != '' and ('dll' in seg_name or 'DLL' in seg_name):
                return symbol_name.replace('.','_')
            if flag == True:
                return None
            point = next_point
            next_point = get_value(next_point)
            count += 1

        return None
        

    # get current block var name list
    def set_block_var(self):
        mapping = get_c_to_asm_mapping(self.here_addr)
        c_code_collect = []
        call_disasm = []
        get_call_code = []
        point = self.here_addr
        block_start = self.get_basic_block_bounds()
        if block_start == None:
            print('[DVC] get block start fail')
            return False
        else:
            print(f'[DVC] get block start address: {hex(block_start)}')

        while  self.here_addr - point <= self.here_addr - block_start and self.here_addr - point >= 0:
            c_code_collect += [c_code for c_code, eb in mapping.items() if eb == point]
            for c_code, eb in mapping.items():
                if eb == point:
                    c_code_collect.append(c_code)
            disasm = idc.GetDisasm(point)
            if 'call' in disasm:
                call_disasm += [c_code for c_code, eb in mapping.items() if eb == point]
            point = idc.prev_head(point)
        
        for a in call_disasm:
            call_amount = []
            for b in c_code_collect:
                if a in b:
                    call_amount.append(b)
            get_call_code.append(max(call_amount, key=len))

        get_call_code = list(set(get_call_code))
        temp = []
        temp += [var for var in self.vars_name for call_code in get_call_code if var in call_code]
        self.block_var = list(set(temp))

        return True

    # get current block start address
    def get_basic_block_bounds(self):
        flowchart = ida_gdl.qflow_chart_t(
            "flowchart",   
            self.func,          
            self.func.start_ea,
            self.func.end_ea,   
            ida_gdl.FC_PREDS 
        )
        for block in flowchart:
            if block.start_ea <= self.func_start < block.end_ea and self.first_block_end == 0:
                self.first_block_end = block.end_ea
            if block.start_ea <= self.here_addr < block.end_ea:
                return block.start_ea

        return None

# get a dict, c_code: address
def get_c_to_asm_mapping(func_ea):
    # func_ea: func address
    cfunc = ida_hexrays.decompile(func_ea)
    c_to_asm_map = {}

    class Visitor(ida_hexrays.ctree_visitor_t):
        def __init__(self):
            ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_PARENTS)

        def visit_expr(self, e):
            c_code = ida_lines.tag_remove(e.print1(None))
            if e.ea != ida_idaapi.BADADDR:
                c_to_asm_map[c_code] = e.ea
            return 0

    visitor = Visitor()
    visitor.apply_to(cfunc.body, None)

    return c_to_asm_map

# create func for call insn
def call_add_func():
    func = ida_funcs.get_func(idc.get_screen_ea())
    func_start = func.start_ea
    func_end = func.end_ea
    c_func = ida_hexrays.decompile(idc.get_screen_ea())
    point = func_start        
    while point <= func_end:
        disasm = idc.GetDisasm(point)
        # 'call    near ptr unk_5D5DACB'
        if ';' in disasm:
            disasm = disasm.split(';')[0].strip()
        if 'call' in disasm and 'unk_' in disasm:
            address = int(disasm.split(' ')[-1].strip()[4:], 16)
            flag = ida_funcs.add_func(address)
            if flag == True:
                print(f'[DVC] decompile call insn at {hex(point)}')
            else:
                print(f'[DVC] fail decompile call insn at {hex(point)}')
            
        point = idc.next_head(point)

    c_func.refresh_func_ctext()


class block_var_check(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        if not ida_dbg.is_debugger_on():
            print("[DVC] Debugger is not running")
            return
        dvc = DVC()
        dvc.block_check = True
        dvc.DVC()
        del dvc

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS


class func_var_check(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        if not ida_dbg.is_debugger_on():
            print("[DVC] Debugger is not running")
            return
        dvc = DVC()
        dvc.block_check = False
        dvc.DVC()
        del dvc

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS
    
class sub_func_disassemble(idaapi.action_handler_t):
    def __init__(self):
        idaapi.action_handler_t.__init__(self)

    def activate(self, ctx):
        call_add_func()

    def update(self, ctx):
        return idaapi.AST_ENABLE_ALWAYS

