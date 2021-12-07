# Helpful-python-scripts
A collection of my scripts for research

## ida_rop_gadgets_search.py
Useage: load script in IDA python command window.
**quick_search_assign_reg** :
reg: reg name, assign value to
src_reg: reg name, stores value
limit: max instruction after target gadget

if you want to search a gadget about assigning value to 'rax', `quick_search_assign_reg('rax','', 1)`
```
['100000607F8', 'pop     rax', 'retn']
['10000065FEC', 'mov     rax, [rax+78h]', 'retn']
['100000660C8', 'mov     rax, cs:rootRamdisk', 'retn']
['1000006682D', 'mov     rax, rdi', 'retn']
['1000006837C', 'pop     rax', 'retn    8']
['1000006E2ED', 'lea     rax, [rax+rdi+8]', 'retn']
```
if you want to assign 'rdi' to 'rsi', `quick_search_assign_reg('rax','', 3)`
```
['10000082138', 'mov     rdi, rsi', 'test    rax, rax', 'jz      short locret_10000082146']
['100000D1CB7', 'lea     rdi, [rsi+8]', 'cld', 'rep stosd', 'retn']
['100001F9708', 'mov     rdi, rsi', 'rep stosd', 'retn']
```

**search_rop_gadgets**:
pattern: a list of regex of instruction
count: max results
limit: max instruction after target gadget

if you want a gadget like this: `mov [rdx], rcx`, `search_rop_gadgets(['mov +\[rdx\], rcx'], 5, 2)`
```
['1000008E5BC', 'mov     [rdx], rcx', 'add     rsp, 88h', 'retn']
['1000009AA78', 'mov     [rdx], rcx', 'xor     eax, eax', 'retn']
['1000009AAC4', 'mov     [rdx], rcx', 'xor     eax, eax', 'retn']
```
