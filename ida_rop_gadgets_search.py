import idautils
import idc
import ida_idp
import re
import idaapi

record = []

segs = {}
for s in idautils.Segments():
    start = idc.get_segm_start(s)
    end = idc.get_segm_end(s)
    name = idc.get_segm_name(s)
    segs[name] = [start, end]

def is_references_contain_special_segment(ea, segname):
	"""
	ea must be a function EA
	segname is segment name, like '.rdata','.text'
	"""
	for x in XrefsTo(ea, 0):
		if x.frm >= segs[segname][0] and  x.frm < segs[segname][1]:
			return True
	return False

def tag_rdata_func():
	for funcea in Functions(segs['.text'][0], segs['.text'][1]):
		if is_references_contain_special_segment(funcea, '.rdata'):
			functionName = GetFunctionName(funcea)
			idc.MakeName(funcea, 'r_'+functionName)

def correct_imported_func_name_addr():
	for funcea in Functions(segs['.text'][0], segs['.text'][1]):
		name = get_func_name(funcea)
		try:
			offset = name.rindex('_')
			if funcea != int(name[offset+1:], 16):
				print(1)
				new = name[:offset]+'_{:X}'.format(funcea)
				print(name, new)
				idc.set_name(funcea, new, SN_CHECK)
		except:
			pass


def quick_search_assign_reg(reg, reg_src = '', count = 100, limit = 3, no_condition_jmp = True):
	regs = ['rax', 'rbx', 'rcx','rdx','rdi','rsi','rsp','rbp','r8','r9','r10','r11','r12','r13','r14','r15','sp', 'spl']
	if reg not in regs:
		print("wrong reg name")
		print("avaliable:", regs)
		return
	if reg_src:
		lea = 'lea +'+reg+', \\[.*'+reg_src+'.*\\]'
		mov = 'mov +'+reg+', '+reg_src
		add = 'add +'+reg+', '+reg_src
		sub = 'sub +'+reg+', '+reg_src
		xchg = 'xchg +'+reg+', '+reg_src
		pattern = [lea,mov,add,sub,xchg]
	else:
		lea = 'lea +'+reg+', '
		mov = 'mov +'+reg+', '
		add = 'add +'+reg+', '
		sub = 'sub +'+reg+', '
		xchg = 'xchg +'+reg+', '
		pop = 'pop +'+reg
		pattern = [lea,mov,add,sub,pop,xchg]
	for each in pattern:
		print('--'+each+'--')
	search_rop_gadgets(pattern, count, limit, no_condition_jmp)

def search_rbp_gadgets(pattern):
	record = []
	start = segs['.text'][0]
	end = segs['.text'][1]
	print(hex(start), hex(end))
	tmp_codes = []
	flag_has_rdi_rbp = False
	record_rbp_ea = 0
	for ea in range(start, end):	
		x = idautils.DecodeInstruction(ea)
		if not x:
			continue
		ret = idc.generate_disasm_line(ea, 1)
		l1 = x.size
		if not re.findall(pattern, ret, re.IGNORECASE):
			continue
		ea2 = ea+l1
		# search in 8 instructions
		for n in range(8):
			x2 = idautils.DecodeInstruction(ea2)
			if not x2:
				# print("unknow error", x2, hex(ea2))
				break # means exist invalid code
			ret2 = idc.generate_disasm_line(ea2, 1)
			l2 = x.size
			if re.findall('call *r', ret2, re.IGNORECASE) or re.findall('jmp *r', ret2, re.IGNORECASE) or re.findall('call *qword ptr \[r', ret2, re.IGNORECASE):
				# print("get call {:x}".format(ea))
				func_addr = idaapi.get_func(ea)
				ea_of_func_begin = func_addr.start_ea
				flag_rbp_base = False
				# only search 12 instructions to check rsp offset
				for m in range(12):
					x3 = idautils.DecodeInstruction(ea_of_func_begin)
					if not x3:
						print("unknow error2", x3, hex(ea_of_func_begin))
						raise(1)
					ret3 = idc.generate_disasm_line(ea_of_func_begin, 1)
					l3 = x3.size
					if re.findall('mov *rbp, rsp', ret3, re.IGNORECASE):
						# print("get rbp base:{:x}".format(ea_of_func_begin))
						flag_rbp_base = True
					if flag_rbp_base:
						if re.findall('sub *rsp, \\d', ret3, re.IGNORECASE):
							offset = ret3[13:-1]
							if offset.startswith('0'):
								offset = offset[1:]
							if not len(offset):
								break # only 1 number
							# print("off",offset, hex(func_addr.start_ea))
							offset = int(offset, 16)
							if offset >= 0x78 and offset <=0x2080:
								# print("get rsp sub:{:x}".format(ea_of_func_begin))
								record.append((func_addr.start_ea, ea2, ea))
								print("get one record:{:X}, {:x}, {:x}".format(func_addr.start_ea, ea2, ea))
							break
					ea_of_func_begin += l3
				break # end search "call reg"
			ea2 += l2
			# print("add main len,", l1)
	print("-"*30)
	for each in record:
		print("{:X}, {:x}, {:x}".format(each[0], each[1], each[2]))
	print("end")

def search_rop_gadgets(pattern, count = 10, limit= 6, no_condition_jmp = True, need_bypass_cfg = False, no_need_return = False):
	finding_count = 0
	record = []
	if not len(pattern):
		print("no pattern")
		return
	start = segs['.text'][0]
	end = segs['.text'][1]
	print(hex(start), hex(end))
	for ea in range(start, end):
		x = idautils.DecodeInstruction(ea)
		if not x:
			continue
		ret = idc.generate_disasm_line(ea, 1)
		l1 = x.size
		for each_pattern in pattern:
			if re.findall(each_pattern, ret, re.IGNORECASE):# mov\w* +\[rcx.*\], rdx
				codes = ['{:X}'.format(ea), ret]
				if no_need_return:
					print(codes)
					record.append(codes)
					finding_count += 1
					continue
				cur_off = l1 # search behind instructions
				cur_ea = ea
				for i in range(limit):
					x = idautils.DecodeInstruction(cur_ea+cur_off)
					if not x:
						break
					n = idc.generate_disasm_line(cur_ea+cur_off, 1)
					codes.append(n)
					cur_off += x.size
					# print n
					# if n[:2] in ['jz','jn','ja','jb','jg','js']:
					# 	break
					if 'call' in n:
						break
					elif 'jmp' in n:
						if 'loc_' in n:# jmp     loc_227CD; jmp     short loc_228C0
							addr = n.split('loc_')[-1]
							cur_ea = int(addr, 16)
							cur_off = 0
							continue
						break # jmp rax, jmp xxxx
					elif 'retf' in n:
						break
					elif n.startswith('ret'):
						if need_bypass_cfg:
							funcea = idaapi.get_func(cur_ea).start_ea
							if not is_references_contain_special_segment(funcea, '.rdata'):
								break

						print(codes)
						record.append(codes)
						finding_count += 1
						break

		if finding_count > count:
			break
	print('-'*30)
	print("result:")
	for i in record:
		print(i)
	print("get result count:{0:d}".format(len(record)))
	print("end")

def check_ret_in_range(ea, limit_ret, is_32bit_support = False):
	behind_ins = []
	flag_has_ret = 0
	_step = 0
	for i in range(limit_ret):
		x = idautils.DecodeInstruction(ea+_step)
		if not x:
			flag_has_ret = 0
			break
		ins = idc.generate_disasm_line(ea+_step, 1)
		behind_ins.append(ins)
		_step += x.size
		if 'leave' in ins: # this means mov rsp, rbp
			flag_has_ret = 0
			break
		if 'ret' in ins:
			flag_has_ret = 1
			break
		if 'jmp' in ins:
			ins_split = ins.split()
			x64_jmp_regs = ['rax','rbx','rcx','rdx','r8','r9','r10','r11','r12','r13','r14','r15','rbp','rsp','rdi','rsi']
			x32_jmp_regs = ['eax','ebx','ecx','edx','ebp','esp','edi','esi']
			regs = x64_jmp_regs
			if is_32bit_support:
				regs = x32_jmp_regs
			if 'loc_' in ins:# jmp     loc_227CD; jmp     short loc_228C0
				addr = ins.split('loc_')[-1]
				ea = int(addr, 16)
				_step = 0
				continue
			elif ins_split[-1] in regs:
				flag_has_ret = 1
				break

	if flag_has_ret:
		return 1, behind_ins
	return 0, []

def search_stack_reverse_gadgets(start = 0, end = 0, step = 8, limit_ret = 8, is_32bit_support = False):
	record = []
	if not start:
		print(hex(segs['.text'][0]), hex(segs['.text'][1]))
		start = segs['.text'][0]
		end = segs['.text'][1]
	else:
		if end > segs['.text'][1] or start > segs['.text'][1]:
			print("warning: start or end offset is bigger than .text range")
			return
		elif end < start:
			print("warning: start < end")
			return
	for ea in range(start, end):
		# print hex(ea)
		x = idautils.DecodeInstruction(ea)
		if not x:
			continue
		ret = idc.generate_disasm_line(ea, 1)
		cur_size = x.size
		# if 'push' in ret:
		# 	if 'r' in ret:
		# 		x = idautils.DecodeInstruction(ea+cur_size)
		# 		if x:
		# 			ins = idc.generate_disasm_line(ea+cur_size, 1)
		# 			if 'ret' in ins:
		# 				record.append(['0',hex(ea), ret, ins])
		# 	continue
		if not 'rsp' in ret:
			if is_32bit_support:
				if not 'esp' in ret:
					continue
			else:
				continue
		if ret.startswith('pop'):
			# print(hex(ea))
			n = step
			while 1:
				ni = n
				flag = 0
				instructions = ['1']
				flag_push = 0
				while 1:
					x = idautils.DecodeInstruction(ea - ni)
					if not x:# if code can't be disassm
						n = n-1
						break
					ins = idc.generate_disasm_line(ea - ni, 1)
					if flag_push:
						instructions.append(ins)
					else:
						if 'push' in ins:
						# for each in ['rax','rdi','rsi','rdx','rcx','r8','r9','rbx','r10','r11','r12','r13','r14','r15','rbp']:
							# if each in ins:
							flag_push = 1
							instructions.append(hex(ea-ni))
							instructions.append(ins)
					ni = ni - x.size
					if ni < 0:
						n = n-1
						break
					if ni == 0:
						flag = 1
						break
				if flag:
					if flag_push:
						instructions.append(ret)
						flag_has_ret, behind_ins = check_ret_in_range(ea + cur_size, limit_ret, is_32bit_support)
						if flag_has_ret:
							record.append(instructions+behind_ins)
					break
				if n == 0:
					break
		elif ret.startswith('xchg'):
			if not '[' in ret:
				flag_has_ret, behind_ins = check_ret_in_range(ea + cur_size, limit_ret, is_32bit_support)
				if flag_has_ret:
					record.append(['2',hex(ea),ret]+behind_ins)
			elif ', rsp' in ret:
				# pass # need to search xchg [rax+xx], rsp
				print(hex(ea), ret)
		elif ret.startswith('mov'):
			if 'rsp,' in ret.split() or (is_32bit_support and 'esp,' in ret.split()):
				flag_has_ret, behind_ins = check_ret_in_range(ea + cur_size, limit_ret, is_32bit_support)
				if flag_has_ret:
					record.append(['3',hex(ea),ret]+behind_ins)
		# elif ret.startswith('lea'): many are "lea rsp,[rbp-28h]"
		# 	if 'rsp,' in ret.split() or (is_32bit_support and 'esp,' in ret.split()):
		# 		flag_has_ret, behind_ins = check_ret_in_range(ea + cur_size, limit_ret)
		# 		if flag_has_ret:
		# 			record.append(['4',hex(ea),ret]+behind_ins)
		# elif ret.startswith('add'): find "add rsp,rbx"? we don't know rsp's value.
		# 	if 'rsp, +'
		# 	if 'rsp,' in ret.split() or (is_32bit_support and 'esp,' in ret.split()):
		# 		flag_has_ret, behind_ins = check_ret_in_range(ea + cur_size, limit_ret)
		# 		if flag_has_ret:
		# 			record.append(['4',hex(ea),ret]+behind_ins)

	print('-'*30)
	print("result:")
	for i in record:
		print(i)
	print("end")


def search_memcpy_xrefs(memcpy_addr):
	rets = []
	for xref in XrefsTo(memcpy_addr, 0):# 0x140844476 is the addr of memcpy
		if idaapi.get_func(xref.frm):
			if idaapi.get_func(xref.frm).size() < 130:
				rets.append((idaapi.get_func(xref.frm).size(), xref.frm))
	rets = sorted(rets)
	for each in rets:
		print('addr: {:x} , size:{:x}'.format(each[1], each[0]))

def Usage():
	print('*'*100)
	print('*'*100)
	usage = """Usage:
	1. run script in ida output windows
	2. run a function for your purpose

	functions:
	search_stack_reverse_gadgets(start = 0, end = 0, step = 8, limit_ret = 8)
		start: start offset of .text
		end  : end offset of .text
		step : max instructions before 'pop rsp'
		limit_ret: max instructions between 'pop rsp' and 'ret'
	eg: if step < 4 or limit_ret < 5, can't find: push rdx; xxx; xxx; xxx; pop rsp; xxx; xxx; xxx; xxx; ret;
	eg: search_stack_reverse_gadgets(); search_stack_reverse_gadgets(step = 5); search_stack_reverse_gadgets(start= xxxx, end=xxx, limit_ret = 4)

	search_rop_gadgets(pattern, count = 10, limit= 6)
		pattern: list of instructions with regex. eg: ['pop *rdi']; ['mov *\\[rdi\\], rax','pop *rax']
		count  : max results to find
		limit  : max instructions after pattern
	eg: search_rop_gadgets(['pop *rdi'], limit = 2) 
		results:
			['1CB7AE', 'pop     rdi', 'pop     rbp', 'retn']
			['1CB8F1', 'pop     rdi', 'pop     rbp', 'retn']
			...

	quick_search_assign_reg(reg, reg_src = '',limit = 3)
		reg    : reg name, assign target. 'rdi', 'rax'...
		reg_src: reg name, assign source.
		limit  : max instructions after pattern
	eg: quick_search_assign_reg('rdi','rax')
		results:
			['1E4AC5', 'mov     rdx, rax', 'xor     eax, eax', 'test    rdx, rdx', 'jz      short locret_1E4A90']
			['360190', 'sub     rdx, rax', 'mov     eax, [rcx+rdx]', 'retn']
			['3B5A11', 'add     rdx, rax', 'lea     rax, [rdi+rdx*2+3Ah]', 'pop     rbp', 'retn']
			['3B5A12', 'add     rdx, rax', 'lea     rax, [rdi+rdx*2+3Ah]', 'pop     rbp', 'retn']
	"""
	print(usage)
	print("^-----------check Usage")

Usage()
