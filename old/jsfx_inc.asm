code_start                equ 0xbbaf0
NSEEL_addfunc_ret_type    equ 0xceb8
NSEEL_PProc_THIS          equ 0x4338
NSEEL_addfunc_varparm_ex  equ 0xd118
NSEEL_PProc_RAM           equ 0x2188
s_kernel32_dll            equ 0xdcd60
GetProcAddress            equ 0xbc120
GetModuleHandleA          equ 0xbc158
GetCurrentProcess         equ 0xbc3e0
%define register_functions_saved_bytes  db 0x48,0x83,0xc4,0x38,0xc3
