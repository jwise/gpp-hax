OUTPUT_FORMAT ("elf32-littlearm", "elf32-bigarm", "elf32-littlearm")
ENTRY(_start)
SEARCH_DIR(.)
GROUP(-lgcc)

MEMORY
{
  rom (rx)  : ORIGIN = 0x0000A000, LENGTH = 0x76000 - 4
  ram (rwx) : ORIGIN = 0x10000000, LENGTH =  64K
  ahb_sram_0 (rwx) : ORIGIN = 0x20000000, LENGTH =  32K
  dram (rwx) : ORIGIN = 0xA0000000, LENGTH =  16M

}

EXTERN(g_pfnVectors)

PROVIDE(stack_size = 0x1000);

SECTIONS
{
  /DISCARD/ : { *crtbegin.o }

  .text :
  {
    CREATE_OBJECT_SYMBOLS
    _start = .;
    *(.isr_vector)
    /* Make sure we pulled in an interrupt vector.  */
    ASSERT (. != g_pfnVectors, "No interrupt vector");
    *(.after_vectors)
    *(.rom)
    *(.rom.b)

    *(EXCLUDE_FILE (*crtbegin.o) .text .text.* .gnu.linkonce.t.*)
    *(.plt)
    *(.gnu.warning)
    *(.glue_7t) *(.glue_7) *(.vfp11_veneer)

    *(.rodata .rodata.* .gnu.linkonce.r.*)

    _table_start = .;
    *(SORT(.table.*));
    _table_end = .;

    *(.ARM.extab* .gnu.linkonce.armextab.*)
    *(.gcc_except_table)
    *(.eh_frame_hdr)
    *(.eh_frame)

    . = ALIGN(4);
    KEEP(*(.init))

    . = ALIGN(4);
    __preinit_array_start = .;
    KEEP (*(.preinit_array))
    __preinit_array_end = .;

    . = ALIGN(4);
    __init_array_start = .;
    KEEP (*(SORT(.init_array.*)))
    KEEP (*(.init_array))
    __init_array_end = .;

    . = ALIGN(0x4);
    KEEP (*crtbegin.o(.ctors))
    KEEP (*(EXCLUDE_FILE (*crtend.o) .ctors))
    KEEP (*(SORT(.ctors.*)))
    KEEP (*crtend.o(.ctors))

    . = ALIGN(4);
    KEEP(*(.fini))

    . = ALIGN(4);
    __fini_array_start = .;
    KEEP (*(.fini_array))
    KEEP (*(SORT(.fini_array.*)))
    __fini_array_end = .;
  }

  /* .ARM.exidx is sorted, so has to go in its own output section.  */
  __exidx_start = .;
  .ARM.exidx :
  {
    *(.ARM.exidx* .gnu.linkonce.armexidx.*)
  } >rom
  __exidx_end = .;
  .text.align :
  {
    . = ALIGN(8);
    _etext = .;
  } >rom

  .data.dram :
  {
    . = ALIGN(8);
    _data_dram = .;
    *(.data.dram);
    . = ALIGN(8);
    _edata_dram = .;
  } >dram AT>rom
  __dram_src  = LOADADDR(.data.dram);
  __dram_dest =     ADDR(.data.dram);
  __dram_size =   SIZEOF(.data.dram);

  .data :
  {
    _data = .;
    *(.cs3.region-head.ram)
    KEEP(*(.jcr))
    *(.got.plt) *(.got)
    *(.shdata)
    *(.data .data.* .gnu.linkonce.d.*)
    *(.ram)
    . = ALIGN (8);
    _edata = .;
  } >ram AT>rom
  __data_src  = LOADADDR(.data);
  __data_dest =     ADDR(.data);
  __data_size =   SIZEOF(.data);

  .bss.dram (NOLOAD) :
  {
    __dram_bss = .;
    *(.dram)
    *(.bss.dram)
    __dram_ebss = .;
  } >dram

  .bss (NOLOAD) :
  {
    _bss = .;
    __bss_start__ = .;
    *(.shbss)
    *(.bss SORT_BY_ALIGNMENT(.bss.*) .gnu.linkonce.b.*)
    *(COMMON)
    *(.ram.b)
    . = ALIGN (8);
    _ebss = .;
    __bss_end__ = .;
  } >ram
  .heap :
  {
    *(.heap)
  } >ram
  .stack (NOLOAD) :
  {
    . = ALIGN(8);
    . += stack_size;
    _stack_top = .;
  } >ram

  _end = .;
  __end = .;

  .stab 0 (NOLOAD) : { *(.stab) }
  .stabstr 0 (NOLOAD) : { *(.stabstr) }
  /* DWARF debug sections.
   * Symbols in the DWARF debugging sections are relative to the beginning
   * of the section so we begin them at 0.  */
  /* DWARF 1 */
  .debug          0 : { *(.debug) }
  .line           0 : { *(.line) }
  /* GNU DWARF 1 extensions */
  .debug_srcinfo  0 : { *(.debug_srcinfo) }
  .debug_sfnames  0 : { *(.debug_sfnames) }
  /* DWARF 1.1 and DWARF 2 */
  .debug_aranges  0 : { *(.debug_aranges) }
  .debug_pubnames 0 : { *(.debug_pubnames) }
  /* DWARF 2 */
  .debug_info     0 : { *(.debug_info .gnu.linkonce.wi.*) }
  .debug_abbrev   0 : { *(.debug_abbrev) }
  .debug_line     0 : { *(.debug_line) }
  .debug_frame    0 : { *(.debug_frame) }
  .debug_str      0 : { *(.debug_str) }
  .debug_loc      0 : { *(.debug_loc) }
  .debug_macinfo  0 : { *(.debug_macinfo) }
  /* SGI/MIPS DWARF 2 extensions */
  .debug_weaknames 0 : { *(.debug_weaknames) }
  .debug_funcnames 0 : { *(.debug_funcnames) }
  .debug_typenames 0 : { *(.debug_typenames) }
  .debug_varnames  0 : { *(.debug_varnames) }

  .note.gnu.arm.ident 0 : { KEEP (*(.note.gnu.arm.ident)) }
  .ARM.attributes 0 : { KEEP (*(.ARM.attributes)) }
  /DISCARD/ : { *(.note.GNU-stack) }
}
