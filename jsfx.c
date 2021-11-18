#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>

#include "patched_bytes.h"

#define NSEEL_API_MAGIC 0x5421999879e0885f

// addresses defined in linker script
int NSEEL_addfunc_ret_type;
int NSEEL_addfunc_varparm_ex;
int NSEEL_PProc_RAM;
int NSEEL_PProc_THIS;
void *eel_gmem_attach;
int strcmp(const char *, const char *);

typedef struct {
	uint64_t magic;
	void *GetFunc;
	void *NSEEL_PProc_RAM;
	void *NSEEL_PProc_THIS;
	void *NSEEL_addfunc_ret_type;
	void *NSEEL_addfunc_varparm_ex;
	void *eel_gmem_attach;
} NSEEL_API_t;

asm(
	".global register_functions \n"
	"register_functions: \n"
	"call _register_functions \n"
	register_functions_patched_bytes
);

void *GetFunc(char *name) {
	if (strcmp(name, "eel_gmem_attach") == 0) {
		return eel_gmem_attach;
	} else {
		return NULL;
	}
}

typedef int (*JSFXRegister_t)(NSEEL_API_t *NSEEL_API);

void _register_functions() {
	NSEEL_API_t NSEEL_API;
	NSEEL_API.magic                    = NSEEL_API_MAGIC;
	NSEEL_API.GetFunc                  = GetFunc;
	NSEEL_API.NSEEL_PProc_RAM          = &NSEEL_PProc_RAM;
	NSEEL_API.NSEEL_PProc_THIS         = &NSEEL_PProc_THIS;
	NSEEL_API.NSEEL_addfunc_ret_type   = &NSEEL_addfunc_ret_type;
	NSEEL_API.NSEEL_addfunc_varparm_ex = &NSEEL_addfunc_varparm_ex;
	NSEEL_API.eel_gmem_attach          = eel_gmem_attach;
	
	HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
	if (kernel32 == NULL) { return; }
	
	BOOL (*EnumProcessModules)(HANDLE, HMODULE *, DWORD, LPDWORD) =
		(BOOL (*)(HANDLE, HMODULE *, DWORD, LPDWORD))GetProcAddress(kernel32, "K32EnumProcessModules");
	if (EnumProcessModules == NULL) { return; }
	
	HMODULE modules[200];
	DWORD cbNeeded;
	if (EnumProcessModules(GetCurrentProcess(), modules, sizeof(modules), &cbNeeded) == 0) { return; }
	if (cbNeeded > sizeof(modules)) { return; }
	for (int i = 0; i < cbNeeded/sizeof(modules[0]); i++) {
		JSFXRegister_t JSFXRegister = (JSFXRegister_t)GetProcAddress(modules[i], "JSFXRegister");
		if (JSFXRegister != NULL) {
			JSFXRegister(&NSEEL_API);
		}
	}
}
