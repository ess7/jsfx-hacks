JSFX_DLL         = jsfx.dll
JSFX_PATCHED_DLL = jsfx_patched.dll

PYTHON3 = python
CC      = gcc
LD      = ld
OBJCOPY = objcopy

CFLAGS = -Wall -fPIC -Os


$(JSFX_PATCHED_DLL): $(JSFX_DLL) jsfx.bin jsfx.map
	$(PYTHON3) patch.py $(JSFX_DLL) $(JSFX_PATCHED_DLL)

jsfx.bin: jsfx_bin.o
	$(OBJCOPY) -O binary -j .text jsfx_bin.o jsfx.bin

jsfx_bin.o jsfx.map: jsfx.o jsfx.ld
	$(LD) -T jsfx.ld -o jsfx_bin.o -Map=jsfx.map jsfx.o

jsfx.o: jsfx.c patched_bytes.h
	$(CC) $(CFLAGS) -c jsfx.c

jsfx.ld patched_bytes.h: $(JSFX_DLL)
	$(PYTHON3) find_addr.py $(JSFX_DLL)

clean:
	rm -f jsfx.ld jsfx.map patched_bytes.h jsfx.o jsfx_bin.o jsfx.bin $(JSFX_PATCHED_DLL)
