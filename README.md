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

## gdb_ida_vmx_locate_svga_function_symbol.py
use gdb attach vmx process.
search "bora/devices/svga/svgaFifo.c" references in ida, begin of function should looks like this:
```c
  if ( !a1 )
  {
    v2 = func_1410000;
    do
      *v2++ = 0LL;
    while ( v2 != &unk_14128B8 );
  }
  ..........
  v12 = &off_1266780;
  ..........
          v12 += 3;
          *v4++ = v13;
          if ( v12 == &unk_1268028 )
          ...................
          v17 = &off_1266300;
          ............
          v17 += 3;
          ++v18;
          if ( &unk_1266768 == v17 )
```
1. change following field of special vmx:
```
set $funclist = $vmx+0x1410000 
set $normal = $vmx+1266300
set $_3d = $vmx+1266780
set $_3d_max=0x516
```
2. run gdb commands in gdb, you will get `svga.log` file in current folder
3. run python script in IDA. the output should looks like this:
```
(0x43b260,"SVGA_UNKNOW_0x509_En_in3d_0x509"),
(0x43b5a0,"SVGA_UNKNOW_0x50a_En_in3d_0x50a"),
(0x43b980,"SVGA_UNKNOW_0x50b_En_in3d_0x50b"),
(0x44a340,"SVGA_UNKNOW_0x50c_En_in3d_0x50c"),
(0x44a430,"SVGA_UNKNOW_0x50d_En_in3d_0x50d"),
```
4. run ida script:
```
import idc
for i in a:
  idc.MakeName(i[0],i[1]+"_{:08X}".format(i[0]))
```
> function name based on [svga3d_cmd.h](https://elixir.bootlin.com/linux/latest/source/drivers/gpu/drm/vmwgfx/device_include/svga3d_cmd.h)

## winindex_patch_info.py
A script to find what file changed of hyper-v's components, based on [winbindex](https://winbindex.m417z.com)
```
Useage:
    this.py winver date
        this.py 1809 202206
    this.py winver date name folder
        this.py 1809 202206 vmbkmclr.sys D:\\tmp\\
    winver: ['1709', '1803', '2004', '1903', '1909', '1809', '11-21H2', '11-22H2', '20H2']
```   
