#!/bin/bash

nasm -f elf64 asm.asm
objcopy --dump-section .text=asm.bin  asm.o

xxd asm.bin
