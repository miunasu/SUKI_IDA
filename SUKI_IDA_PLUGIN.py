import sys
import os
import idaapi
import ida_kernwin

sys.path.append(os.path.dirname(__file__))

from SUKI_IDA import *

# plugin function switch
DynamicVarCheck_switch = True
REAI_switch = True
ExportFuncCheck_switch = True

# DVC hotkey
HOTKEY_block_var_check = "Shift-B"
HOTKEY_func_var_check = "Shift-A"
HOTKEY_sub_func_disassemble = "Shift-F"

# EFC hotkey
HOTKEY_export_func_check = "Ctrl-Alt-E"



def register_actions():
    
# Register actions
    # DVC    
    if DynamicVarCheck_switch == True:
        block_var_check = idaapi.action_desc_t(
            "DVC:block_var_check",
            "block var check",  
            DynamicVarCheck.block_var_check(),
            HOTKEY_block_var_check, 
            "block var check",
            0
        )

        func_var_check = idaapi.action_desc_t(
            "DVC:func_var_check",
            "func var check",  
            DynamicVarCheck.func_var_check(),
            HOTKEY_func_var_check, 
            "func var check",
            0
        )
        
        sub_func_disassemble = idaapi.action_desc_t(
            "DVC:sub_func_disassemble",
            "sub func disassemble",  
            DynamicVarCheck.sub_func_disassemble(),
            HOTKEY_sub_func_disassemble, 
            "sub func disassemble",
            0
        )

        idaapi.register_action(block_var_check)
        idaapi.register_action(func_var_check)
        idaapi.register_action(sub_func_disassemble)

        idaapi.attach_action_to_menu("Debugger/DVC/", "DVC:block_var_check", idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu("Debugger/DVC/", "DVC:func_var_check", idaapi.SETMENU_APP)
        idaapi.attach_action_to_menu("Debugger/DVC/", "DVC:sub_func_disassemble", idaapi.SETMENU_APP)

    # REAI
    if REAI_switch == True:
        func_analyze = idaapi.action_desc_t(
            "REAI:func_analyze",
            "func_analyze",  # 
            REAI.func_analyze(),
            "", 
            "AI work for you!",
            0
        )

        exception_code_check = idaapi.action_desc_t(
            "REAI:exception_code_check",
            "exception_code_check",  # 
            REAI.exception_code_check_action(),
            "", 
            "exception code check",
            0
        )

        call_topology_print = idaapi.action_desc_t(
            "REAI:call_topology_print",
            "call_topology_print",  # 
            REAI.call_topology_print(),
            "", 
            "call topology print",
            0
        )

        conversation = idaapi.action_desc_t(
            "REAI:conversation",
            "conversation",   
            REAI.conversation(),
            "", 
            "LLM conversation",
            0
        )

        idaapi.register_action(func_analyze)
        idaapi.register_action(exception_code_check)
        idaapi.register_action(call_topology_print)
        idaapi.register_action(conversation)

        # EFC
    if ExportFuncCheck_switch == True:
        export_func_check = idaapi.action_desc_t(
            "EFC:export_func_check",
            "export_func_check",  # 
            ExportFuncCheck.export_func_check(),
            HOTKEY_export_func_check, 
            "export func check",
            0
        )

        idaapi.register_action(export_func_check)

        idaapi.attach_action_to_menu("View/Open subviews/Export Check", "EFC:export_func_check", idaapi.SETMENU_APP)


def unregister_actions():
    # DVC
    if DynamicVarCheck_switch == True:
        idaapi.unregister_action("DVC:block_var_check") 
        idaapi.unregister_action("DVC:func_var_check")
        idaapi.unregister_action("DVC:sub_func_disassemble")
    
    # REAI
    if REAI_switch == True:
        idaapi.unregister_action("REAI:func_analyze")
        idaapi.unregister_action("REAI:exception_code_check") 
        idaapi.unregister_action("REAI:call_topology_print") 
        idaapi.unregister_action("REAI:conversation")

    # EFC
    if ExportFuncCheck_switch == True:
        idaapi.unregister_action("EFC:export_func_check")

class SUKI_IDA_PLUGIN(idaapi.plugin_t):
    flags = idaapi.PLUGIN_KEEP
    comment = "SUKI_IDA"
    help = "SUKI_IDA"
    wanted_name = "SUKI_IDA"

    def init(self):
        global REAI_switch
        # config check
        # REAI
        if REAI_switch == True and (REAI.API_KEY == "api_key" or REAI.API_URL == "api_url" or REAI.MODEL == "model name"): 
            ida_kernwin.info("You turn on REAI but not set the API_KEY, API_URL and MODEL in REAI.py. REAI will not load")
            REAI_switch = False

        # init
        register_actions()
        # DVC
        if DynamicVarCheck_switch == True:
            print('[DVC] DVC is ready')
            print('[DVC] Block var check: Shift-B\nFunc var check: Shift-A\nSub func disassemble: Shift-F')

        # REAI
        if REAI_switch == True:
            self.menu = ContextMenuHooks()
            self.menu.hook()
            REAI.CLI = REAI.talk_with_LLM()
            REAI.CLI.register()
            print('[REAI] REAI is ready')
            print('[REAI] Right click on pseudocode view')    
            

        # EFC 
        if ExportFuncCheck_switch == True:
            print('[EFC] EFC is ready')
            print('[EFC] Export func check: Ctrl-Alt-E')

        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        # DVC
        if DynamicVarCheck_switch == True:
            print('[DVC] Block var check: Shift-B\nFunc var check: Shift-A\nSub func disassemble: Shift-F')

        # REAI
        if REAI_switch == True:
            print('[REAI] Right click on pseudocode view')    
    
        # EFC
        if ExportFuncCheck_switch == True:
            print('[EFC] Export func check: Ctrl-Alt-E')

        return

    def term(self):

        unregister_actions()
        
        # REAI
        if REAI_switch == True:
            self.menu.unhook()
            REAI.CLI.unregister()

def PLUGIN_ENTRY():
    return SUKI_IDA_PLUGIN()

class ContextMenuHooks(idaapi.UI_Hooks):
    def finish_populating_widget_popup(self, form, popup):
        # Add actions to the context menu of the Pseudocode view
        if idaapi.get_widget_type(form) == idaapi.BWN_PSEUDOCODE:
            # REAI
            if REAI_switch == True:
                idaapi.attach_action_to_popup(form, popup, "REAI:func_analyze", "REAI/")
                idaapi.attach_action_to_popup(form, popup, "REAI:exception_code_check", "REAI/")
                idaapi.attach_action_to_popup(form, popup, "REAI:call_topology_print", "REAI/")
                idaapi.attach_action_to_popup(form, popup, "REAI:conversation", "REAI/")