all:
	@echo Specify 'msvc' or 'mingw' target.

msvc:
	lib /def:ntdll86.def /out:ntdll86.lib /machine:x86
	lib /def:ntdll64.def /out:ntdll64.lib /machine:x64
	del /q ntdll86.exp
	del /q ntdll64.exp

mingw:
	dlltool -d ntdll86.def -l libntdll86.a
	dlltool -d ntdll64.def -l libntdll64.a
