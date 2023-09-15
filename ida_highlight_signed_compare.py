import idaapi
import idc
import ida_kernwin


# Enable_Signed_TAG = True
class Signed_compare_highlight(idaapi.plugin_t):
    flags = 0
    comment = "A plugin to highlight signed compare"
    help = "Auto highlight signed compare"
    wanted_name = "signed_compare_highlight"
    wanted_hotkey = ""

    def init(self):
        idaapi.msg("signed_compare_highlight Plugin Initialized\n")
        self.hx_view_hooks = MyHooks()
        self.hx_view_hooks.hook()
        # ida_kernwin.add_hotkey("Alt+Shift+F5", self.enable_it)
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        pass

    def enable_it(self):
        global Enable_Signed_TAG
        if Enable_Signed_TAG:
            print("diable tag")
            Enable_Signed_TAG = False
        else:
            print("enable tag")
            Enable_Signed_TAG = True

    def term(self):
        self.hx_view_hooks.unhook()
        # ida_kernwin.del_hotkey("Alt+Shift+F5")
        idaapi.msg("signed_compare_highlight Plugin Terminated\n")

class MyHooks(idaapi.Hexrays_Hooks):
    def double_click(self, vu, shift_state):
        global Enable_Signed_TAG
        ea = vu.cfunc.entry_ea
        decompiler = idaapi.decompile(ea)
        pseudocode = decompiler.get_pseudocode()
        for i, line in enumerate(pseudocode):
            if any(op in line.line for op in ['>', '<', '>=', '<=']):
                phead = idaapi.ctree_item_t()
                pitem = idaapi.ctree_item_t()
                ptail = idaapi.ctree_item_t()
                ret = decompiler.get_line_item(line.line, 0, False, phead, pitem, ptail)
                if ret and pitem.it:
                    asm_ea = pitem.it.ea
                    asm_line = idc.GetDisasm(asm_ea)
                    if any(op in asm_line for op in ['jg', 'jng', 'jl', 'jge', 'jle', 'jnl', 'js']):
                        # idaapi.tag_remove(line.line)
                        # if Enable_Signed_TAG:
                            line.bgcolor = 0x55ff55 # green
                            # print("highlighted 1 line")
                        # else:
                            # idaapi.tag_remove(line.line)
                            # print("remove 1 line tag")
        # if Enable_Signed_TAG:
        #     print("diable tag")
        #     Enable_Signed_TAG = False
        # else:
        #     print("enable tag")
        #     Enable_Signed_TAG = True
        ida_kernwin.refresh_idaview_anyway()
        return 1

def PLUGIN_ENTRY():
    return Signed_compare_highlight()
