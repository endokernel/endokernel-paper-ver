OUTPUT_FORMAT("elf64-x86-64", "elf64-x86-64", "elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)
ENTRY(shim_start)

SECTIONS
{
  /* Read-only sections, merged into text segment; */
  . = SEGMENT_START("text-segment", 0) + SIZEOF_HEADERS;
  .note.gnu.build-id : { *(.note.gnu.build-id) }
  .hash          : { *(.hash) }
  .gnu.hash      : { *(.gnu.hash) }
  .dynsym        : { *(.dynsym) }
  .dynstr        : { *(.dynstr) }
  .gnu.version   : { *(.gnu.version) }
  .gnu.version_d : { *(.gnu.version_d) }
  .gnu.version_r : { *(.gnu.version_r) }
  .rela.dyn       :
     {
      *(.rela.init)
      *(.rela.text .rela.text.* .rela.gnu.linkonce.t.*)
      *(.rela.fini)
      *(.rela.rodata .rela.rodata.* .rela.gnu.linkonce.r.*)
      *(.rela.data .rela.data.* .rela.gnu.linkonce.d.*)
      *(.rela.tdata .rela.tdata.* .rela.gnu.linkonce.td.*)
      *(.rela.tbss .rela.tbss.* .rela.gnu.linkonce.tb.*)
      *(.rela.ctors)
      *(.rela.dtors)
      *(.rela.got)
      *(.rela.bss .rela.bss.* .rela.gnu.linkonce.b.*)
      *(.rela.ldata .rela.ldata.* .rela.gnu.linkonce.l.*)
      *(.rela.lbss .rela.lbss.* .rela.gnu.linkonce.lb.*)
      *(.rela.lrodata .rela.lrodata.* .rela.gnu.linkonce.lr.*)
      *(.rela.ifunc)
    }
  .rela.plt      :
    {
      *(.rela.plt)
      *(.rela.iplt)
    }
  .init          : { *(.init) }
  .plt           : { *(.plt) *(.iplt) }
  .text :
  {
    /* the rest of text segments */
    code_start = .;
    *(.text .stub .text.*);
    . = ALIGN(8);
    code_end = .;
  }
  .fini          : { *(.fini) }
  .rodata :
  {
    /* the rest of rodata */
    *(.rodata .rodata.*)
  }
  .eh_frame_hdr  : { *(.eh_frame_hdr) }
  .eh_frame      : ONLY_IF_RO { *(.eh_frame) }

  /* now adjust the address for the data segment */
  . = DATA_SEGMENT_ALIGN (CONSTANT (MAXPAGESIZE), CONSTANT (COMMONPAGESIZE));
  .eh_frame      : ONLY_IF_RW { *(.eh_frame) }
  .ctors         : { *(.ctors) }
  .dtors         : { *(.dtors) }
  .jcr           : { *(.jcr) }
  .dynamic       : { *(.dynamic) }
  .got           : { *(.got) *(.igot) }
  .got.plt       : { *(.got.plt) *(.igot.plt) }
  . = DATA_SEGMENT_RELRO_END (0, .);
  .data :
  {
    /* the rest of data segment */
    *(.data .data.*);
  }
  .bss            :
  {
    *(.bss .bss.*)
    *(COMMON)
  }
  . = DATA_SEGMENT_END(.);

  . = ALIGN(CONSTANT(COMMONPAGESIZE));
  .syscall_trampoline : 
  {
    trampoline_start = .;
    *(.syscall_trampoline);
    FILL(0xCC);
    . = ALIGN(CONSTANT(COMMONPAGESIZE) * 2);
    trampoline_end = .;
  }
}
