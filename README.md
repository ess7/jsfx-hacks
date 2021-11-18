# jsfx-hacks
Modified Reaper `jsfx.dll` (Windows x64) for adding custom functions in C

### Patching with supplied vcdiff
Requires `xdelta3`
1. Check that the SHA1 matches the one in `diffs/sha1sums` for your version  
```
5a3fdc8c6a1b824532ea27bbadc20c0e9a05c1c6 *jsfx640.dll
37d9f12df6af5115f4762ed43a3da12e5d7acb8f *jsfx640_patched.dll

# sha1sum jsfx.dll
5a3fdc8c6a1b824532ea27bbadc20c0e9a05c1c6 *jsfx.dll
```
2. `xdelta3 -d -s jsfx.dll diffs/jsfx640.vcdiff jsfx_patched.dll`
3. Check the SHA1 of patched DLL
```
# sha1sum jsfx.dll
37d9f12df6af5115f4762ed43a3da12e5d7acb8f *jsfx_patched.dll
```

### Building the patched DLL from source
Requires `python3` with `pefile`, `make`, `gcc x86_64-w64-mingw32`, `ld`, `objcopy`
1. Inspect `Makefile` for possible changes
2. Run `make`
