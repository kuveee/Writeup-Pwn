section .text

global _start

_start:
    push 29816
    mov rax,0x742e67616c662f2e
    push rax
    mov rdi,rsp
    xor rsi,rsi
    xor rdx,rdx
    mov rax,0x02
    syscall

    mov rdi,rax
    mov rsi,rsp
    sub rsi,0x50
    mov rdx,0x50
    mov rax,0
    syscall

    mov rdi,1
    mov rax,1
    syscall



