import idaapi
import ida_struct
import ida_typeinf

def strip_table_name(name):
	charac = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
	n = name.replace('6B','')
	n = n.replace('$','')
	if '?' in n:
		while n[0:1] not in charac:
			n = n[1:]
		n = n.replace('?','')
	if 'GUID_' in n:
		n = n[:n.index('GUID_')-3:]
	if '@' in n:
		n = '_'.join([x for x in n.split('@') if x])
	return n

def strip_func_name(name):
	n = name.replace('$','')
	if '@@' in n:
		i = n.index('@@')
		n = n[:i]
	if '?' in n:
		n = n.replace('?','')
	if '@' in n:
		n = '_'.join([x for x in n.split('@') if x])
	return n

def func_args(func_ea):
	tif = ida_typeinf.tinfo_t()
	funcdata = ida_typeinf.func_type_data_t()
	ida_nalt.get_tinfo(tif, func_ea)
	tif.get_func_details(funcdata)
	args = []
	for pos, argument in enumerate(funcdata):
		args.append((pos, argument.type, argument.name))
	rettype = funcdata.rettype
	return args, rettype


recent_struct_info = None
def construct_vftable(start = 0):
	if not start:
		start = idc.here()
	print("start: 0x{:x}".format(start))
	end = start + 8
	while 1:
		name = get_name(end)
		if name:
			print(name)
			break
		end += 8

	struct_info = {}
	vf_name = strip_table_name(get_name(start))+'_vtl'
	struct_info['name'] = vf_name
	fields = []
	for off in range(start, end, 8):
		addr = get_qword(off)
		func_name = strip_func_name(get_name(addr))
		args, rettype = func_args(addr)
		fields.append((func_name, addr, rettype, args))

	string = "struct {} ".format(vf_name)+"{\n"
	for i in range(len(fields)):
		member_types = ''
		member_name = 'func_{}_{:x}_{:x}h'.format(fields[i][0], fields[i][1], i*8)
		if len(''.format(fields[i][2])) == 0:
			member_types += "  __int64 (__fastcall*{})(".format(member_name)
		else:
			member_types +="  {} (__fastcall*{})(".format(fields[i][2], member_name)
		args = fields[i][3]
		for j in range(len(args)):
			if not j == 0:
				member_types +=","
			member_types += "{} {}".format(args[j][1], args[j][2])
		member_types += ');\n'
		if struct_info.get('members'):
			struct_info['members'].append((member_name, member_types))
		else:
			struct_info['members'] = [(member_name, member_types)]
		string += member_types
	string += '};'
	string = string.replace('.', '_')
	print(string)
	global recent_struct_info
	recent_struct_info = struct_info

def add_my_struct_to_local():
	global recent_struct_info
	members = recent_struct_info['members']
	struct_name = recent_struct_info['name']
	struc_id = ida_struct.get_struc_id(struct_name)
	if struc_id == idaapi.BADADDR:
		sid = ida_struct.add_struc(idaapi.BADADDR, struct_name, 0)
		sptr = ida_struct.get_struc(sid)
		for pos, each in enumerate(members):
			member_name = each[0]
			member_type = each[1]
			print(member_name, member_type)
			tif = ida_typeinf.tinfo_t()
			ida_typeinf.parse_decl(tif, None, member_type, 0)
			ida_struct.add_struc_member(sptr, member_name, -1, idaapi.FF_DATA| idaapi.FF_QWORD, None, 8)
			ida_struct.set_member_tinfo(sptr, sptr.get_member(pos), 0, tif, ida_struct.SET_MEMTI_COMPATIBLE)
	else:
		print("structure already exist!")
