import struct
import re
import sys
import copy
import pefile


LEA_RCX = b'\x48\x8d\x0d'
LEA_RDX = b'\x48\x8d\x15'
LEA_R9  = b'\x4c\x8d\x0d'
ADD_RSP = b'\x48\x83\xc4'
MOV_QWORD_PTR_RAX = b'\x48\x89\x05'
CALL    = b'\xe8'
RET     = b'\xc3'
POP_REG  = b'(\x41?[\x58-\x5f])'
CALL_REG = b'(\x41?\xff[\xd0-\xd7])'


def align(x, alignment):
	return (x + alignment-1) & ~(alignment-1)

def get_section(pe, section):
	for s in pe.sections:
		if bytes(section, 'ascii') in s.Name:
			return s

def get_rip_rel_rva(match, name, section):
	rip_ofs = struct.unpack('<l', match.group(name))[0]
	return rip_ofs + match.start(name) + 4 + section.VirtualAddress

def get_string(match, name, section, pe):
	rva = get_rip_rel_rva(match, name, section)
	try:
		string = str(pe.get_data(rva, 100), 'ascii')
	except:
		return None
	i = string.find('\x00')
	if i > 0:
		return string[:i]
	else:
		return None


jsfx = pefile.PE(sys.argv[1])
text = get_section(jsfx, '.text')

'''
   (6.40)
   1800421fc 48 8d 0d fd de 07 00   LEA      RCX,[s_strlen_1800c0100] = "strlen"
   180042203 48 89 44 24 20         MOV      qword ptr [RSP + local_18],RAX=>LAB_18003d8d8
   180042208 ba 01 00 00 00         MOV      EDX,0x1
   18004220d 41 b8 01 00 00 00      MOV      R8D,0x1
   180042213 4c 8d 0d 1e 21 fc ff   LEA      R9,[NSEEL_PProc_THIS]
   18004221a e8 99 ac fc ff         CALL     NSEEL_addfunc_ret_type
'''
def find_nseel(func):
	pproc = None
	addfunc = None
	for match in re.finditer(
			LEA_RCX + b'(?P<name>....)' +
			          b'.{,50}?' +
			LEA_R9  + b'(?P<pproc>....)' +
			CALL    + b'(?P<addfunc>....)',
			text.get_data(),
			re.DOTALL):
		if get_string(match, 'name', text, jsfx) == func:
			pproc = get_rip_rel_rva(match, 'pproc', text)
			addfunc = get_rip_rel_rva(match, 'addfunc', text)
			return addfunc, pproc

NSEEL_addfunc_ret_type,   NSEEL_PProc_THIS = find_nseel('strlen')
NSEEL_addfunc_varparm_ex, _                = find_nseel('sprintf')
_,                        NSEEL_PProc_RAM  = find_nseel('convolve_c')
'''
   (6.40)
   180042ea1 48 8d 15 ec d6 07 00   LEA      RDX,[s_jsfx_gfx_1800c0594] = "jsfx_gfx"
   180042ea8 45 33 c0               XOR      R8D,R8D
   180042eab 45 33 c9               XOR      R9D,R9D
   180042eae e8 45 ea ff ff         CALL     FUN_1800418f8
   180042eb3 48 83 c4 38            ADD      RSP,0x38      <----- jmp patch
   180042eb7 c3                     RET
   (6.42 dev 1117)
   1800423f4 48 8d 15 d9 c0 07 00   LEA      RDX,[s_jsfx_gfx_1800be4d4] = "jsfx_gfx"
   1800423fb 45 33 c0               XOR      R8D,R8D
   1800423fe 45 33 c9               XOR      R9D,R9D
   180042401 e8 46 e9 ff ff         CALL     FUN_180040d4c
   180042406 48 83 c4 38            ADD      RSP,0x38
   18004240a 5d                     POP      RBP
   18004240b 41 5f                  POP      R15
   18004240d c3                     RET
'''
for match in re.finditer(
		LEA_RDX + b'(?P<name>....)' +
		b'\x45\x33\xc0' +
		b'\x45\x33\xc9' +
		CALL + b'....' +
		b'(?P<epilog>' + ADD_RSP+b'.' + POP_REG+b'*' + RET + b')',
		text.get_data(),
		re.DOTALL):
	if get_string(match, 'name', text, jsfx) == 'jsfx_gfx':
		register_patch_addr = match.start('epilog') + text.VirtualAddress
		register_functions_patched_bytes = match.group('epilog')
'''
   (6.40)
   180088dd5 48 8d 0d 3c ac 03 00   LEA      param_1,[s_eel_gmem_attach_1800c3a18] = "eel_gmem_attach"
   180088ddc ff d5                  CALL     RBP
   ...
   ...
   180088e02 48 89 05 87 4d 06 00   MOV      qword ptr [eel_gmem_attach],RAX
'''
for match in re.finditer(
		LEA_RCX + b'(?P<name>....)' +
		# b'\xff\xd5' +
		CALL_REG +
		b'.{,100}?' +
		MOV_QWORD_PTR_RAX + b'(?P<eel_gmem_attach>....)',
		text.get_data(),
		re.DOTALL):
	if get_string(match, 'name', text, jsfx) == 'eel_gmem_attach':
		eel_gmem_attach = get_rip_rel_rva(match, 'eel_gmem_attach', text)
'''
   (6.40)
   1800bb8a0 48 2b d1               SUB      _Str2,_Str1
   1800bb8a3 4c 8b ca               MOV      R9,_Str2
   1800bb8a6 f6 c1 07               TEST     _Str1,0x7
   1800bb8a9 74 1b                  JZ       LAB_1800bb8c6
'''
strcmp = text.get_data().index(b'\x48\x2b\xd1\x4c\x8b\xca\xf6\xc1\x07\x74\x1b') + text.VirtualAddress

imports = []
for entry in jsfx.DIRECTORY_ENTRY_IMPORT:
	if entry.dll.lower() == b'kernel32.dll':
		for imp in entry.imports:
			imports.append((imp.name.decode('ascii'), imp.address-jsfx.OPTIONAL_HEADER.ImageBase))

with open('jsfx.ld', 'w') as f:
	f.write('''origin                    = 0x{:x};
NSEEL_addfunc_ret_type    = 0x{:x};
NSEEL_addfunc_varparm_ex  = 0x{:x};
NSEEL_PProc_RAM           = 0x{:x};
NSEEL_PProc_THIS          = 0x{:x};
eel_gmem_attach           = 0x{:x};
strcmp                    = 0x{:x};
register_patch_addr       = 0x{:x};
'''.format(
	align(jsfx.sections[-1].VirtualAddress + jsfx.sections[-1].Misc_VirtualSize, jsfx.OPTIONAL_HEADER.SectionAlignment),
	NSEEL_addfunc_ret_type,
	NSEEL_addfunc_varparm_ex,
	NSEEL_PProc_RAM,
	NSEEL_PProc_THIS,
	eel_gmem_attach,
	strcmp,
	register_patch_addr))
	for name, addr in imports:
		if name in ('GetModuleHandleA', 'GetProcAddress', 'GetCurrentProcess'):
			f.write('{:<25s} = 0x{:x};\n'.format('__imp_'+name, addr))
	f.write('''SECTIONS {
	.text origin : {
		*(.text .rdata)
	}
	/DISCARD/ : {
		*(*)
	}
}
''')

with open('patched_bytes.h', 'w') as f:
	f.write('#define register_functions_patched_bytes ".byte {} \\n"'.format(','.join(map(hex, register_functions_patched_bytes))))

