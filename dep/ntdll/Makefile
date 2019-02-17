# This Makefile is compatible with mingw32-make and nmake.
# To build msvc libs: nmake msvc
# To build mingw libs: mingw32-make mingw

all:
	@echo Specify 'msvc' or 'mingw' target.

msvc:
	# Microsoft's lib.exe exports mangled names no matter what.
	# ntdll.dll exports unmangled names. Libs built by mingw's
	# dlltool also work in msvc so use that on 32bit.
	# If you do not feel like installing msys2 to build 32bit
	# import lib you can always submit a PR. Thanks!
	# lib /def:ntdll86.def /out:ntdll86.lib /machine:x86
	# del /q ntdll86.exp
	lib /def:ntdll64.def /out:ntdll64.lib /machine:x64
	del /q ntdll64.exp

mingw:
	/mingw32/bin/dlltool -d ntdll86.def -l libntdll86.a -k -f--32
	/mingw64/bin/dlltool -d ntdll64.def -l libntdll64.a
