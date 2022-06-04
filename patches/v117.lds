OUTPUT_FORMAT("elf32-littlearm", "elf32-bigarm",
	      "elf32-littlearm")
OUTPUT_ARCH(arm)

SECTIONS
{
  . = 0x3f238;
  .text.trampoline : {
    *(.text.trampoline);
  }

  . = 0x78000;
  .text : {
    *(.start);
    *(.text);
    *(SORT(.table.*));
  }
  .rodata : { *(.rodata); }
}
