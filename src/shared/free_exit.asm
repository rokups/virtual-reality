;
; MIT License
;
; Copyright (c) 2019 Rokas Kupstys
;
; Permission is hereby granted, free of charge, to any person obtaining a
; copy of this software and associated documentation files (the "Software"),
; to deal in the Software without restriction, including without limitation
; the rights to use, copy, modify, merge, publish, distribute, sublicense,
; and/or sell copies of the Software, and to permit persons to whom the
; Software is furnished to do so, subject to the following conditions:
;
; The above copyright notice and this permission notice shall be included in
; all copies or substantial portions of the Software.
;
; THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
; IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
; FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
; THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
; LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
; FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
; DEALINGS IN THE SOFTWARE.
;
; This file implements a function that frees passed module (which is a module
; that contains currently executing code) and exits current thread without
; returning to already freed code. 32bit version is in win32.cpp
;
.code

extern ExitThread:  near
extern VirtualFree: near
public free_module_exit_thread

free_module_exit_thread:
    sub  rsp, 20h
    push 0                          ; thread exit code
    push 0C000h                     ; MEM_RELEASE | MEM_DECOMMIT
    push 0                          ; size
    push rcx                        ; module
    mov  rax, ExitThread            ; ExitThread
    push rax
    jmp  VirtualFree                ; VirtualFree

END