import idautils
import idc
import re

DEBUG = False
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

def print_arg(pseudocode, func_name, arg_index):
    global g, DEBUG
    flag = 0
    c = 0
    g = []
    flag_multi_line = False
    args = []
    for line in pseudocode:
        _line = format_ida_pseudocode_line(line.line)
        g.append(line.line)
        # print(line.line)
        # print(_line)
        if flag_multi_line:
            if DEBUG:
                print('m', _line)
            c += 1
            if c == arg_index:
                flag_multi_line = False
                ret = re.findall('(\w+) ,', _line)
                arg = ret[0]
                arg = arg.replace('u', '')
                arg = arg.replace('i64', '')
                try:
                    if arg.startswith('0x'):
                        arg = int(arg, 16)
                    else:
                        arg = int(arg, 10)
                except:
                    args.append((-1, arg))
                    continue
                args.append((1, arg))

        elif func_name in _line.split(' ') and func_name + '(' in _line.replace(' ',''):
            if DEBUG:
                print('1', _line.split(' '))
                print('1', _line)
            if arg_index == 3:
                regex = '\(.*?,.*?, (.*?),'
            elif arg_index == 2:
                regex = '\(.*?,(.*?),'
            elif arg_index == 1:
                regex = '\((.*?),'

            ret = re.findall(regex, _line)
            if not len(ret):
                flag_multi_line = True
                c = 0
                continue
            arg = ret[0]
            t = arg.split(' ')
            # print(t)
            for i in range(len(t), 0, -1): # get last not NULL string
                if t[i-1]:
                    arg = t[i-1]
                    break
            arg = arg.replace('u', '')
            arg = arg.replace('i64', '')
            if arg.count('.') > 1:# for x.x.x string
                args.append((-1, arg))
                continue                
            try:
                if arg.startswith('0x'):
                    arg = int(arg, 16)
                else:
                    arg = int(arg, 10)
            except:
                args.append((-1, arg))
                continue
            args.append((1, arg))
    return args


def get_func_xref_arg(ref_func_name, func_ea, arg_index):
    arg_dic = {}
    index_dic = {}
    for xref in idautils.XrefsTo(func_ea):
        func_name = get_func_name(xref.frm)
        if func_name:
            if DEBUG:
                print('f', func_name)
            decompiler = idaapi.decompile(idc.get_name_ea_simple(func_name))
            pseudocode = decompiler.get_pseudocode()
            if pseudocode:
                args = print_arg(pseudocode, ref_func_name, arg_index)
                for each in args:
                    if each[0] == -1:
                        if func_name in arg_dic.keys():
                            arg_dic[func_name].append(each[1])
                        else:
                            arg_dic[func_name] = [each[1]]
                    else:
                        if func_name in index_dic.keys():
                            index_dic[func_name].append(each[1])
                        else:
                            index_dic[func_name] = [each[1]]

    print("="*40+ref_func_name+'='*40)
    out_string = ''
    for key in arg_dic.keys():
        for each in arg_dic[key]:
            out_string += "arg: {} func: {}\n".format(each, key)
    out_string += '\n'
    for key in index_dic.keys():
        index_list = list(set(index_dic[key]))
        for each in index_list:
            out_string += "index: {:d} func: {}\n".format(each, key)
    print(out_string)
    print("/"*40+'/'*40)
