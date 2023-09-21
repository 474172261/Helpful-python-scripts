import idautils
import idc
import re

def get_func_name(ea):
    func = idaapi.get_func(ea)
    if func:
        return idc.get_func_name(func.start_ea)
    return None

def get_pseudocode(ea):
    f = idaapi.get_func(ea)
    if not f:
        return None

    pseudocode = []
    decompiled_func = idaapi.decompile(f.start_ea)
    if decompiled_func:
        pseudocode = str(decompiled_func).split('\n')
    
    return pseudocode

def format_ida_pseudocode_line(line):
    ret = re.findall('[\{\};\+\-\*/=><_!\.a-zA-Z0-9,\(\)\[\]]*', line)
    rest = []
    for each in ret:
        if len(each) and '(000000' not in each:
            rest.append(each)
    return ' '.join(rest)

g = None
def print_arg1_in_new_line(pseudocode, func_name):
    global g
    flag = 0
    c = 0
    arg1 = None
    g = []
    for line in pseudocode:
        g.append(line.line)
        if flag:
            if not arg1:
                _line = format_ida_pseudocode_line(line.line)
                print(_line)
                # print(re.findall('(0?x?\w+)u?', _line))
                arg1 = re.findall('(0?x?\w+)u?', _line)[0]
                break
            # if not callback
        if func_name in line.line:
            flag = 1
    arg1 = arg1.replace('u', '')
    if arg1.startswith('0x'):
        arg1 = int(arg1, 16)
    else:
        arg1 = int(arg1, 10)
    return arg1

def print_arg3(pseudocode, func_name, arg_index):
    global g
    flag = 0
    c = 0
    g = []
    flag_multi_line = False
    args = []
    for line in pseudocode:
        _line = format_ida_pseudocode_line(line.line)
        g.append(line.line)
        if flag_multi_line:
            # print(_line)
            c += 1
            if c == 3:
                flag_multi_line = False
                ret = re.findall('(\w+) ,', _line)
                arg3 = ret[0]
                arg3 = arg3.replace('u', '')
                arg3 = arg3.replace('i64', '')
                try:
                    if arg3.startswith('0x'):
                        arg3 = int(arg3, 16)
                    else:
                        arg3 = int(arg3, 10)
                except:
                    args.append((-1, arg3))
                    continue
                args.append((1, arg3))

        elif func_name in _line.split(' '):
            # print(_line)
            if arg_index == 3:
                regex = '\(.*?,.*?, (.*?),'
            elif arg_index == 2:
                regex = '\(.*?,(.*?),'
            ret = re.findall(regex, _line)
            if not len(ret):
                flag_multi_line = True
                c = 0
                continue
            arg3 = ret[0]
            t = arg3.split(' ')
            # print(t)
            for i in range(len(t), 0, -1): # get last not NULL string
                if t[i-1]:
                    arg3 = t[i-1]
                    break
            arg3 = arg3.replace('u', '')
            arg3 = arg3.replace('i64', '')
            try:
                if arg3.startswith('0x'):
                    arg3 = int(arg3, 16)
                else:
                    arg3 = int(arg3, 10)
            except:
                args.append((-1, arg3))
                continue
            args.append((1, arg3))
    return args


def get_func_xref_arg1(ref_func_name, func_ea):
    for xref in idautils.XrefsTo(func_ea):
        func_name = get_func_name(xref.frm)
        if func_name:
            # print(func_name)
            decompiler = idaapi.decompile(idc.get_name_ea_simple(func_name))
            pseudocode = decompiler.get_pseudocode()
            if pseudocode:
                arg1 = print_arg1_in_new_line(pseudocode, ref_func_name)
                print("index: {:d} func: {}".format( arg1, func_name))
                break

def get_func_xref_arg(ref_func_name, func_ea, arg_index):
    for xref in idautils.XrefsTo(func_ea):
        func_name = get_func_name(xref.frm)
        if func_name:
            # print(func_name)
            decompiler = idaapi.decompile(idc.get_name_ea_simple(func_name))
            pseudocode = decompiler.get_pseudocode()
            if pseudocode:
                args = print_arg3(pseudocode, ref_func_name, arg_index)
                for each in args:
                    if each[0] == -1:
                        print("arg: {} func: {}".format( each[1], func_name))
                    else:
                        print("index: {:d} func: {}".format( each[1], func_name))


get_func_xref_arg('CryptDecodeObject', 0x1800A5198, 2)
