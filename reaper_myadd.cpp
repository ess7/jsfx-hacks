#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdint.h>

#include <reaper_plugin.h>
#include <ns-eel.h>


#define NSEEL_API_MAGIC 0x2985ac757f70b25c
typedef struct {
	uint64_t     magic;
	void *       (*GetFunc)(char *);
	NSEEL_PPPROC NSEEL_PProc_RAM;
	NSEEL_PPPROC NSEEL_PProc_THIS;
	void         (*NSEEL_addfunc_ret_type)(const char *name, int np, int ret_type,  NSEEL_PPPROC pproc, void *fptr, eel_function_table *destination);
	void         (*NSEEL_addfunc_varparm_ex)(const char *name, int min_np, int want_exact, NSEEL_PPPROC pproc, EEL_F (NSEEL_CGEN_CALL *fptr)(void *, INT_PTR, EEL_F **), eel_function_table *destination);
	void **      (*eel_gmem_attach)(const char *nm, bool is_alloc);
} NSEEL_API_t;

#undef  NSEEL_addfunc_retval
#define NSEEL_addfunc_retval(NSEEL_API,name,np,pproc,fptr) \
  NSEEL_API->NSEEL_addfunc_ret_type(name,np,1,pproc,(void *)(fptr),NSEEL_ADDFUNC_DESTINATION)  


// function to be called from jsfx
static EEL_F NSEEL_CGEN_CALL add(void *opaque, EEL_F *a, EEL_F *b) {
	return *a + *b;
}

extern "C" {

__declspec(dllexport)
int JSFXRegister(NSEEL_API_t *NSEEL_API) {
	// make sure we are using the correct API struct
	if (NSEEL_API->magic != NSEEL_API_MAGIC) {
		return 0;
	}
	// test GetFunc
	if (NSEEL_API->GetFunc("eel_gmem_attach") != NSEEL_API->eel_gmem_attach) {
		return 0;
	}
	NSEEL_addfunc_retval(NSEEL_API, "myadd", 2, NSEEL_API->NSEEL_PProc_THIS, add);
	return 1;
}

REAPER_PLUGIN_DLL_EXPORT
int REAPER_PLUGIN_ENTRYPOINT(REAPER_PLUGIN_HINSTANCE hInstance, reaper_plugin_info_t *rec) {
	if (rec == NULL) {
		return 0;
	}
	return 1;
}

}
