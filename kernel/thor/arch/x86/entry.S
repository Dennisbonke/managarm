#include <thor-internal/arch/asm.h>

.text
#ifdef THOR_SECURITY_TEST_HOOKS
.macro THOR_SECURITY_PRE_IDLE
	incq %gs:THOR_GS_SECURITY_PRE_IDLE_COUNT
.endm
.macro THOR_SECURITY_POST_IDLE
	incq %gs:THOR_GS_SECURITY_POST_IDLE_COUNT
.endm
#else
.macro THOR_SECURITY_PRE_IDLE
.endm
.macro THOR_SECURITY_POST_IDLE
.endm
#endif
.global thorRtEntry
thorRtEntry:
	# enable SSE support
	mov %cr0, %rax
	and $0xFFFFFFFFFFFFFFFB, %rax # disable EM
	or $2, %rax # enable MP
	mov %rax, %cr0

	mov %cr4, %rax
	or $0x200, %rax # enable OSFXSR
	or $0x400, %rax # enable OSXMMEXCPT
	mov %rax, %cr4

	call thorInitialize
	call thorRunConstructors
	call thorMain
	ud2

.text
.global enableIntsAndHaltForever
enableIntsAndHaltForever:
	sti
halt_loop:
	THOR_SECURITY_PRE_IDLE
	hlt
	THOR_SECURITY_POST_IDLE
	jmp halt_loop

	.section .note.GNU-stack,"",%progbits
