MEMORY {
    IMG_RAM (rwx) : ORIGIN = 0x01000000, LENGTH = 0x1000000
    ROM (rwx) : ORIGIN = 0x0a000000, LENGTH = 0x1000000
    RAM (rx) : ORIGIN = 0x0b000000, LENGTH = 0x1000000
}

SECTIONS {
    .img : {
        *(.img)
    } > IMG_RAM

    .text : {
        *(.text)
    } > ROM

    .rodata : {
        *(.rodata)
    } > ROM

    .dynsym : {
        *(.dynsym)
    } > ROM

    .dynstr : {
        *(.dynstr)
    } > ROM

    .rela.dyn : {
        *(.rela.dyn)
    } > ROM

    .rela.plt : {
        *(.rela.plt)
    } > ROM

    .plt : {
        *(.plt)
    } > ROM

    .dynamic : {
        *(.dynamic)
    } > RAM

    .got : {
        *(.got)
    } > RAM

    .got.plt : {
        *(.got.plt)
    } > RAM

    .data : {
        *(.data)
    } > RAM

    .bss : {
        *(.bss)
    } > RAM
}

ENTRY(_start)
