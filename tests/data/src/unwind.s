@ Hand-written functions covering the EHABI unwinding directives.
@ Assemble with: clang --target=armv7a-none-eabi -c unwind.s
	.syntax unified
	.text
	.arm

	.globl f_save_lr
	.type f_save_lr, %function
f_save_lr:
	.fnstart
	.save {r4, lr}
	push {r4, lr}
	pop {r4, pc}
	.fnend

	.globl f_save_pad
	.type f_save_pad, %function
f_save_pad:
	.fnstart
	.save {r4-r11, lr}
	push {r4-r11, lr}
	.pad #16
	sub sp, sp, #16
	add sp, sp, #16
	pop {r4-r11, pc}
	.fnend

	.globl f_vfp_large
	.type f_vfp_large, %function
f_vfp_large:
	.fnstart
	.save {r4, r5, lr}
	push {r4, r5, lr}
	.vsave {d8-d15}
	vpush {d8-d15}
	.vsave {d16-d17}
	vpush {d16-d17}
	.pad #0x300
	sub sp, sp, #0x300
	add sp, sp, #0x300
	vpop {d16-d17}
	vpop {d8-d15}
	pop {r4, r5, pc}
	.fnend

	.globl f_cantunwind
	.type f_cantunwind, %function
f_cantunwind:
	.fnstart
	.cantunwind
	bx lr
	.fnend

	.globl f_setfp
	.type f_setfp, %function
f_setfp:
	.fnstart
	.save {r4, r7, lr}
	push {r4, r7, lr}
	.setfp r7, sp, #4
	add r7, sp, #4
	sub sp, r7, #4
	pop {r4, r7, pc}
	.fnend

	.globl f_low_regs
	.type f_low_regs, %function
f_low_regs:
	.fnstart
	.save {r0-r3, r11, lr}
	push {r0-r3, r11, lr}
	pop {r0-r3, r11, pc}
	.fnend

	.globl f_pr1_descriptors
	.type f_pr1_descriptors, %function
f_pr1_descriptors:
	.fnstart
	.personalityindex 1
	.save {r4, lr}
	push {r4, lr}
	nop
	nop
	pop {r4, pc}
.Lpad1:
	b .Lpad1
	.handlerdata
	@ cleanup: length 8, offset 4
	.short 8, 4
	.long .Lpad1(prel31)
	@ catch(...) by reference: length 4|1, offset 8
	.short 5, 8
	.long .Lpad1(prel31) + 0x80000000
	.long 0xffffffff
	@ catch type_info: length 4|1, offset 4
	.short 5, 4
	.long .Lpad1(prel31)
	.long _ZTIi(target2)
	@ exception spec with landing pad: length 12, offset 0|1, 1 type
	.short 12, 1
	.long 0x80000001
	.long _ZTIi(target2)
	.long .Lpad1(prel31)
	@ terminator
	.long 0
	.fnend

	.globl f_pr2_descriptors
	.type f_pr2_descriptors, %function
f_pr2_descriptors:
	.fnstart
	.personalityindex 2
	.save {r4-r6, lr}
	push {r4-r6, lr}
	pop {r4-r6, pc}
.Lpad2:
	b .Lpad2
	.handlerdata
	@ catch(...) fail with 32-bit scope: length 8|1, offset 0
	.long 9, 0
	.long 0
	.long 0xfffffffe
	@ exception spec throw(), no landing pad
	.long 8, 1
	.long 0
	.long 0
	.fnend

	.globl f_generic
	.type f_generic, %function
f_generic:
	.fnstart
	.personality __gxx_personality_v0
	.save {r11, lr}
	push {r11, lr}
	pop {r11, pc}
	.handlerdata
	@ An LSDA: omitted lpstart, omitted ttype, udata4 call sites, empty table.
	.byte 0xff, 0xff, 0x03, 0x00
	.fnend

	.globl f_raw
	.type f_raw, %function
f_raw:
	.fnstart
	@ Return address authentication (PACBTI-M) and spare opcodes, emitted raw.
	.unwind_raw 0, 0xb4
	.unwind_raw 0, 0xb5
	.unwind_raw 8, 0x80, 0x00
	bx lr
	.fnend
