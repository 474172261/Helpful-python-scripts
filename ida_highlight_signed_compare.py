import idaapi
import idc
import ida_kernwin
import idautils


class MyPlugin(idaapi.plugin_t):
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
        ea = vu.cfunc.entry_ea
        decompiler = idaapi.decompile(ea)
        pseudocode = decompiler.get_pseudocode()
        for i, line in enumerate(pseudocode):
            if any(op in line.line for op in ['>', '<', '>=', '<=']):
                phead = idaapi.ctree_item_t()
                pitem = idaapi.ctree_item_t()
                ptail = idaapi.ctree_item_t()
                for x in range(150):# I just assume this line contains max 150 characters
                    ret = decompiler.get_line_item(line.line, x, False, phead, pitem, ptail)
                    if ret and pitem.it:
                        asm_ea = pitem.it.ea
                        asm_line = idc.GetDisasm(asm_ea)
                        # print(asm_line, hex(asm_ea))
                        if 'cmp' in asm_line:# cmovl won't appear in this loop, so we need to check following assembly, I guess we can find jmp in 6 instructions.
                            flag = 0
                            for i in range(6):
                                x3 = idautils.DecodeInstruction(asm_ea)
                                asm_ea = x3.size + asm_ea
                                asm_line = idc.GetDisasm(asm_ea)
                                # print(asm_line, hex(asm_ea))
                                if any(op in asm_line for op in ['jg', 'jng', 'jl', 'jge', 'jle', 'jnl', 'js', 'jns', 'cmovg', 'cmovge', 'cmovl', 'cmovle', 'cmovs', 'cmovns']):
                                    flag = 1 # yes, we found condition jump
                                    break
                                elif any(op in asm_line for op in ['ja', 'jb', 'jz', 'jnz', 'cmove', 'cmovne', 'cmova', 'cmovae', 'cmovb', 'cmovbe', 'jae', 'jbe', 'jmp']):
                                    break # if we find other jump, we assume that it's not signed jump. this may ignore some special cases.
                            if flag:
                                line.bgcolor = 0x55ff55 # green
                                print("highlighted 1 line")
                                break
                        else:
                            if any(op in asm_line for op in ['jg', 'jng', 'jl', 'jge', 'jle', 'jnl', 'js', 'jns', 'cmovg', 'cmovge', 'cmovl', 'cmovle', 'cmovs', 'cmovns']):
                                    line.bgcolor = 0x55ff55 # green
                                    print("highlighted 1 line")
                                    break
        print("signed highlight")
        ida_kernwin.refresh_idaview_anyway()
        return 0

def PLUGIN_ENTRY():
    return MyPlugin()
