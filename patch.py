import struct
import re
import sys
import copy
import pefile


def align(x, alignment):
	return (x + alignment-1) & ~(alignment-1)

def get_section(pe, section):
	for s in pe.sections:
		if bytes(section, 'ascii') in s.Name:
			return s

def get_addr_from_map(func):
	with open('jsfx.map') as map:
		for l in map:
			l = re.split('\s+', l.strip())
			if len(l) >= 2 and l[1] == func:
				return int(l[0], 16)

def jmp_patch(pe, where, target):
	pe.set_bytes_at_rva(where, b'\xe9' + struct.pack('<l', target-(where+5)))


jsfx = pefile.PE(sys.argv[1])

jmp_patch(jsfx, get_addr_from_map('register_patch_addr'), get_addr_from_map('register_functions'))

text2 = copy.copy(get_section(jsfx, '.text'))
text2.Name = b'.text2\x00\x00'
text2.VirtualAddress = align(jsfx.sections[-1].VirtualAddress + jsfx.sections[-1].Misc_VirtualSize, 
	jsfx.OPTIONAL_HEADER.SectionAlignment)
end_of_file = max((s.PointerToRawData + s.SizeOfRawData for s in jsfx.sections))
text2.PointerToRawData = align(end_of_file,	jsfx.OPTIONAL_HEADER.FileAlignment)
max_section_file_offset = max((s.get_file_offset() for s in jsfx.sections))
text2.set_file_offset(max_section_file_offset + text2.sizeof())

assert len(jsfx.__data__) <= text2.PointerToRawData
bin = open('jsfx.bin', 'rb').read(-1)

text2.SizeOfRawData = align(len(bin), jsfx.OPTIONAL_HEADER.FileAlignment)
text2.Misc_VirtualSize = align(len(bin), 16)

jsfx.__data__ += \
	b'\x00'*(text2.PointerToRawData - len(jsfx.__data__)) + \
	bin + b'\x00'*(text2.SizeOfRawData - len(bin))

jsfx.__structures__.append(text2)
jsfx.FILE_HEADER.NumberOfSections += 1
jsfx.OPTIONAL_HEADER.SizeOfImage = text2.VirtualAddress + text2.Misc_VirtualSize
jsfx.OPTIONAL_HEADER.CheckSum = jsfx.generate_checksum()

jsfx.write(sys.argv[2])
