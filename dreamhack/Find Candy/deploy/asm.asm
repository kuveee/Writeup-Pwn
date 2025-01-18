section .text
global _start
_start:
  mov rsi,0x080000000000     ;dia chi can ghi
  mov rdx,0x1000             ; so luong can ghi

L1: 
  xor rax,rax
  inc rax                     ; rax = 1
  mov rdi,rax
  syscall
  add rsi,0x1000             ;cong tiep 0x1000 bytes va so sanh voi target , neu chua bang thi tiep tuc ghi
  cmp rsi,0x0800fffff000
  JNE L1
