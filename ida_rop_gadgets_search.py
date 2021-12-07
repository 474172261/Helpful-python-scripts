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

def search_rop_gadgets(count = 10):
	index = 0
	for ea in range(SegStart(BeginEA()), SegEnd(BeginEA())):
		ret = idc.generate_disasm_line(ea, 1)
		# print ret
		if not ret:
			continue
		if 'r8,' in ret:# or 'r9d,' in ret or 'r9w,' in ret:
			if ret[:4] in ('cmp ','test'):
				continue
			x = idautils.DecodeInstruction(ea)
			if not x:
				break
			l = x.size
			codes = ['{:X}'.format(ea), ret]
			for i in range(5):
				n = idc.generate_disasm_line(ea+l, 1)
				if n:
					codes.append(n)
					x = idautils.DecodeInstruction(ea+l)
					if not x:
						break
					l += x.size
					# print n
					if 'call' in n:
						break
					elif 'jmp' in n:
						break
					elif n.startswith('ret'):
						record.append(codes)
						index += 1
						break
		if index > count:
			break
	for i in record:
		print i

def quick_search_assign_reg(reg, reg_src = '',limit = 3):
	regs = ['rax', 'rbx', 'rcx','rdx','rdi','rsi','rsp','rbp','r8','r9','r10','r11','r12','r13','r14','r15']
	if reg not in regs:
		print "wrong reg name"
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
		print '--'+each+'--'
	search_rop_gadgets(pattern, 100, limit)


def search_rop_gadgets(pattern, count = 10, limit= 6):
	index = 0
	record = []
	if not len(pattern):
		print "no pattern"
		return
	start = segs['.text'][0]
	end = segs['.text'][1]
	print hex(start), hex(end)
	for ea in range(start, end):
		x = idautils.DecodeInstruction(ea)
		if not x:
			continue
		ret = idc.generate_disasm_line(ea, 1)
		l1 = x.size
		for each_pattern in pattern:
			if re.findall(each_pattern, ret):# mov\w* +\[rcx.*\], rdx
				codes = ['{:X}'.format(ea), ret]
				l = l1
				for i in range(limit):
					x = idautils.DecodeInstruction(ea+l)
					if not x:
						break
					n = idc.generate_disasm_line(ea+l, 1)
					codes.append(n)
					l += x.size
					# print n
					if 'call' in n:
						break
					elif 'jmp' in n:
						break
					elif 'retf' in n:
						break
					elif 'ret' in n:
						# if is_references_contain_special_segment(funcea, '.rdata'):
						print codes
						record.append(codes)
						index += 1
						break

		if index > count:
			break
	print '-'*30
	for i in record:
		print i

def check_ret_in_range(ea, limit_ret):
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
		if 'ret' in ins:
			flag_has_ret = 1
			break
	if flag_has_ret:
		return 1, behind_ins
	return 0, []

def search_stack_reverse_gadgets(start = 0, end = 0, step = 8, limit_ret = 8):
	record = []
	if not start:
		print(hex(segs['.text'][0]), hex(segs['.text'][1]))
		start = segs['.text'][0]
		end = segs['.text'][1]
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
			continue
		if ret.startswith('pop'):
			print hex(ea)
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
						flag_has_ret, behind_ins = check_ret_in_range(ea + cur_size, limit_ret)
						if flag_has_ret:
							record.append(instructions+behind_ins)
					break
				if n == 0:
					break
		elif ret.startswith('xchg'):
			if not '[' in ret:
				flag_has_ret, behind_ins = check_ret_in_range(ea + cur_size, limit_ret)
				if flag_has_ret:
					record.append(['2',hex(ea),ret]+behind_ins)
		elif ret.startswith('mov'):
			if 'rsp,' in ret.split():
				flag_has_ret, behind_ins = check_ret_in_range(ea + cur_size, limit_ret)
				if flag_has_ret:
					record.append(['3',hex(ea),ret]+behind_ins)


	for i in record:
		print i

def search_memcpy_xrefs():
	for xref in XrefsTo(0x140844476, 0):# 0x140844476 is the addr of memcpy
		if idaapi.get_func(xref.frm):
			if idaapi.get_func(xref.frm).size() < 130:
				print '{:x}'.format(xref.frm)

