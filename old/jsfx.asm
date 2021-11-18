; yasm -f bin jsfx.asm -o jsfx.bin
; objdump -D -Mintel,x86-64 -b binary -m i386 --adjust-vma=[code_start] jsfx.bin
[MAP symbols]
bits 64

%include "jsfx_inc.asm"

org code_start

NSEEL_API_MAGIC     equ 0x5421999879e0885f

register_functions:
	.MAX_MODULES equ 200
	.LOCAL_SIZE  equ 8*(5 + .MAX_MODULES + 1)
	.ALIGN       equ 8
	push rbx
	sub rsp, .LOCAL_SIZE+.ALIGN+32
	
	%define .NSEEL_API  rsp+32
	%define .lphModule  rsp+32+8*(5)
	%define .lpcbNeeded rsp+32+8*(5+.MAX_MODULES)

	; NSEEL_API struct
	mov rax, NSEEL_API_MAGIC
	mov [.NSEEL_API    ], rax
	lea rax, [rel NSEEL_PProc_RAM]
	mov [.NSEEL_API+1*8], rax
	lea rax, [rel NSEEL_PProc_THIS]
	mov [.NSEEL_API+2*8], rax
	lea rax, [rel NSEEL_addfunc_ret_type]
	mov [.NSEEL_API+3*8], rax
	lea rax, [rel NSEEL_addfunc_varparm_ex]
	mov [.NSEEL_API+4*8], rax
	
	lea rcx, [rel s_kernel32_dll]  ; lpModuleName
	call [rel GetModuleHandleA]    ; kernel32 = GetModuleHandleA("kernel32.dll")
	test rax, rax
	jz .exit
	
	mov rcx, rax                         ; hModule
	lea rdx, [rel s_EnumProcessModules]  ; lpProcName
	call [rel GetProcAddress]            ; EnumProcessModules = GetProcAddress(kernel32, "K32EnumProcessModules")
	test rax, rax
	jz .exit
	mov rbx, rax
	
	call [rel GetCurrentProcess]
	
	mov rcx, rax             ; hProcess
	lea rdx, [.lphModule]    ; lphModule
	mov r8d, 8*.MAX_MODULES  ; cb
	lea r9, [.lpcbNeeded]    ; lpcbNeeded
	call rbx                 ; EnumProcessModules(GetCurrentProcess(), lphModule, 8*.MAX_MODULES, &lpcbNeeded)
	test eax, eax 
	jz .exit
	cmp dword [.lpcbNeeded], 8*.MAX_MODULES
	jg .exit
	
	xor ebx, ebx                       ;  for (ebx = 0; ebx < lpcbNeeded; ebx += 8) {
	.loop:
		cmp ebx, [.lpcbNeeded]
		jge .exit_loop
		mov rcx, [.lphModule+rbx]      ;    hModule
		lea rdx, [rel s_JSFXRegister]  ;    lpProcName
		call [rel GetProcAddress]      ;    JSFXRegister = GetProcAddress(lphModule + ebx, "JSFXRegister")
		add ebx, 8
		test rax, rax
		jz .loop
		lea rcx, [.NSEEL_API]
		call rax                       ;    if (JSFXRegister != NULL) { JSFXRegister(NSEEL_API) }
		jmp .loop
	.exit_loop                         ;  }
	
	.exit:
	add rsp, .LOCAL_SIZE+.ALIGN+32
	pop rbx
	register_functions_saved_bytes

s_EnumProcessModules: db 'K32EnumProcessModules',0
s_JSFXRegister:       db 'JSFXRegister',0
