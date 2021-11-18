// original, 0x180042df0 6.40/x64
void register_functions(void)

{
  if (instances != 0) {
    instances = instances + 1;
    return;
  }
  instances = instances + 1;
  FUN_18000d1fc();
  FUN_180043acc();
  EEL_fft_register();
  EEL_mdct_register();
  EEL_string_register();
  EEL_atomic_register();
  EEL_misc_register();
  NSEEL_addfunc_varparm_ex("midisend_str",2,1,(char *)NSEEL_PProc_THIS,&LAB_180034db8,(LPVOID *)0x0)
  ;
  NSEEL_addfunc_varparm_ex("midirecv_str",2,1,(char *)NSEEL_PProc_THIS,&LAB_1800345ac,(LPVOID *)0x0)
  ;
  eel_lice_register();
  FUN_1800418f8(DAT_1800ed940,"jsfx_gfx",0,(HICON)0x0);
  return;
}


// patched
void register_functions(void)

{
  HMODULE kernel32;
  FARPROC EnumProcessModules;
  HANDLE currentProcess;
  INT_PTR ret;
  FARPROC JSFXRegister;
  ulonglong i;
  NSEEL_API_t NSEEL_API;
  HMODULE modules [200];
  DWORD cbNeeded;
  
  if (instances != 0) {
    instances = instances + 1;
    return;
  }
  instances = instances + 1;
  FUN_18000d1fc();
  FUN_180043acc();
  EEL_fft_register();
  EEL_mdct_register();
  EEL_string_register();
  EEL_atomic_register();
  EEL_misc_register();
  NSEEL_addfunc_varparm_ex("midisend_str",2,1,(char *)NSEEL_PProc_THIS,&LAB_180034db8,(LPVOID *)0x0)
  ;
  NSEEL_addfunc_varparm_ex("midirecv_str",2,1,(char *)NSEEL_PProc_THIS,&LAB_1800345ac,(LPVOID *)0x0)
  ;
  eel_lice_register();
  FUN_1800418f8(DAT_1800ed940,"jsfx_gfx",0,(HICON)0x0);
  NSEEL_API.magic = 0x5421999879e0885f;
  NSEEL_API.NSEEL_PProc_RAM = NSEEL_PProc_RAM;
  NSEEL_API.NSEEL_PProc_THIS = NSEEL_PProc_THIS;
  NSEEL_API.NSEEL_addfunc_ret_type = NSEEL_addfunc_ret_type;
  NSEEL_API.NSEEL_addfunc_varparm_ex = NSEEL_addfunc_varparm_ex;
  kernel32 = GetModuleHandleA("kernel32.dll");
  if (kernel32 != (HMODULE)0x0) {
    EnumProcessModules = GetProcAddress(kernel32,"K32EnumProcessModules");
    if (EnumProcessModules != (FARPROC)0x0) {
      currentProcess = GetCurrentProcess();
      ret = (*EnumProcessModules)(currentProcess,modules,0x640,&cbNeeded);
      if (((int)ret != 0) && ((int)cbNeeded < 0x641)) {
        i = 0;
        while ((int)i < (int)cbNeeded) {
          JSFXRegister = GetProcAddress(*(HMODULE *)((longlong)modules + i),"JSFXRegister");
          i = (ulonglong)((int)i + 8);
          if (JSFXRegister != (FARPROC)0x0) {
            (*JSFXRegister)(&NSEEL_API);
          }
        }
      }
    }
  }
  return;
}





