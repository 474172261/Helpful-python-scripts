# Helpful-python-scripts
A collection of my scripts for research

## ida_rop_gadgets_search.py
search rop gadgets by ida

```
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
				pattern: list of instructions with regex. eg: ['pop *rdi']; ['mov *\[rdi\], rax','pop *rax']  
				count  : max results to find  
				limit  : max instructions after pattern  
		eg: search_rop_gadgets(['pop *rdi'], limit = 2)   
				results:  
						['1CB7AE', 'pop     rdi', 'pop     rbp', 'retn']  
						['1CB8F1', 'pop     rdi', 'pop     rbp', 'retn']  

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

```

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
> Before use it, make sure you has folder `D:\tmp\tmp_index\`, if you needs new file info, make sure you deleted json files in that folder, let script auto download it again.

```
Useage:
    this.py  date winver name folder
        this.py  202206 1809 vmbkmclr.sys D:\\tmp\\
    this.py cmp mounth winver1 winver2 ...
        this.py cmp 202206 1809
        this.py cmp 202206 1809 20H2 11-21H1
    winver: ['1703', '1507', '1607','1709', '1803', '2004', '1903', '1909', '1809', '11-21H2', '11-22H2', '20H2'(-22H2)]
```

## ida_highlight_signed_compare.py
This script helps you check signed conditions in pseudocode windows, it will help you to find a bug like this:
```
struct aa{
......
   int f1;
} x;
char b[16];
x.f1 = *(int*)value_ptr_we_controlled;
......
if(x.f1 > 15) x.f1 = 15;
memset(b, 0, x.f1);
```

useage: 
1. put file into ida's plugin folder, eg: C:\Users\your user name\AppData\Roaming\Hex-Rays\IDA Pro\plugins\
2. reload IDA
3. double click white space in pseudocode window, the signed compare backgroud color will be set to green.
> If you want to clear it, just press `F5`.


2023/9/18: update news, support multiple conditions in one line(notice, length of one line must be smaller than 150, if you want to support more longer, change script by yourself)



2023/9/21: update news, support more special conditions, eg: `sub`, `add` ... will change SF flag.

![image](https://github.com/474172261/Helpful-python-scripts/blob/main/demo-signed_compare_highlight.gif)

## ida_get_func_xrefs_arg.py
a script to find a function's references and its argument value.
Useage:
run script in ida python command console. if you want to find 'CryptDecodeObject's references and its arg2, run `get_func_xref_arg('CryptDecodeObject', 0x1800A5198, 2)`
