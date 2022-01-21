# Helpful-python-scripts
A collection of my scripts for research

## ida_rop_gadgets_search.py
Usage:
1. run script in ida output windows
2. run a function for your purpose

functions:  
&emsp;	search_stack_reverse_gadgets(start = 0, end = 0, step = 8, limit_ret = 8)  
&emsp;&emsp;		start: start offset of .text  
&emsp;&emsp;		end  : end offset of .text  
&emsp;&emsp;		step : max instructions before 'pop rsp'  
&emsp;&emsp;		limit_ret: max instructions between 'pop rsp' and 'ret'  
&emsp;	eg: if step < 4 or limit_ret < 5, can't find: push rdx; xxx; xxx; xxx; pop rsp; xxx; xxx; xxx; xxx; ret;  
&emsp;	eg: search_stack_reverse_gadgets(); search_stack_reverse_gadgets(step = 5); search_stack_reverse_gadgets(start= xxxx, end=xxx, limit_ret = 4)  
  
&emsp;	search_rop_gadgets(pattern, count = 10, limit= 6)  
&emsp;&emsp;		pattern: list of instructions with regex. eg: ['pop *rdi']; ['mov *\\[rdi\\], rax','pop *rax']  
&emsp;&emsp;		count  : max results to find  
&emsp;&emsp;		limit  : max instructions after pattern  
&emsp;	eg: search_rop_gadgets(['pop *rdi'], limit = 2)   
&emsp;&emsp;		results:  
&emsp;&emsp;&emsp;			['1CB7AE', 'pop     rdi', 'pop     rbp', 'retn']  
&emsp;&emsp;&emsp;			['1CB8F1', 'pop     rdi', 'pop     rbp', 'retn']  

&emsp;	quick_search_assign_reg(reg, reg_src = '',limit = 3)  
&emsp;&emsp;		reg    : reg name, assign target. 'rdi', 'rsi'...  
&emsp;&emsp;		reg_src: reg name, assign source.  
&emsp;&emsp;		limit  : max instructions after pattern  
&emsp;	eg: quick_search_assign_reg('rdi','rsi')  
&emsp;&emsp;		results:  
&emsp;&emsp;&emsp;			['1E4AC5', 'mov     rdx, rax', 'xor     eax, eax', 'test    rdx, rdx', 'jz      short locret_1E4A90']  
&emsp;&emsp;&emsp;			['360190', 'sub     rdx, rax', 'mov     eax, [rcx+rdx]', 'retn']  
&emsp;&emsp;&emsp;			['3B5A11', 'add     rdx, rax', 'lea     rax, [rdi+rdx*2+3Ah]', 'pop     rbp', 'retn']  
&emsp;&emsp;&emsp;			['3B5A12', 'add     rdx, rax', 'lea     rax, [rdi+rdx*2+3Ah]', 'pop     rbp', 'retn']  

