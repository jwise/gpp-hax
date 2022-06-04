.section .text.trampoline
.global trampoline
.code 16
.thumb_func
.syntax unified
.type trampoline, %function
trampoline:
	b.w entry

.section .rodata

#define NATIVE(name, ofs) name: ; .long ofs ; .globl name

NATIVE(ui_set_overlay_params, 0x18ca3)
NATIVE(ui_set_overlay_text, 0x18c07)
NATIVE(ui_modal_and_wait, 0x18dbb)
