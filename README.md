# Helpful-python-scripts
A collection of my scripts for research

## ida_rop_gadgets_search.py
Usage:
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
		reg    : reg name, assign target. 'rdi', 'rsi'...
		reg_src: reg name, assign source.
		limit  : max instructions after pattern
	eg: quick_search_assign_reg('rdi','rsi')
		results:
			['1E4AC5', 'mov     rdx, rax', 'xor     eax, eax', 'test    rdx, rdx', 'jz      short locret_1E4A90']
			['360190', 'sub     rdx, rax', 'mov     eax, [rcx+rdx]', 'retn']
			['3B5A11', 'add     rdx, rax', 'lea     rax, [rdi+rdx*2+3Ah]', 'pop     rbp', 'retn']
			['3B5A12', 'add     rdx, rax', 'lea     rax, [rdi+rdx*2+3Ah]', 'pop     rbp', 'retn']

