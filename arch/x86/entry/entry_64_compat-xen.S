/*
 * Compatibility mode system call entry point for x86-64.
 *
 * Copyright 2000-2002 Andi Kleen, SuSE Labs.
 */
#include "calling.h"
#include <asm/asm-offsets.h>
#include <asm/current.h>
#include <asm/errno.h>
#include <asm/ia32_unistd.h>
#include <asm/thread_info.h>
#include <asm/segment.h>
#include <asm/irqflags.h>
#include <asm/asm.h>
#include <asm/smap.h>
#include <linux/linkage.h>
#include <linux/err.h>

	.section .entry.text, "ax"

#ifdef CONFIG_PARAVIRT
ENTRY(native_usergs_sysret32)
	swapgs
	sysretl
ENDPROC(native_usergs_sysret32)
#endif

/*
 * 32-bit SYSENTER instruction entry.
 *
 * SYSENTER loads ss, rsp, cs, and rip from previously programmed MSRs.
 * IF and VM in rflags are cleared (IOW: interrupts are off).
 * SYSENTER does not save anything on the stack,
 * and does not save old rip (!!!) and rflags.
 *
 * Arguments:
 * eax  system call number
 * ebx  arg1
 * ecx  arg2
 * edx  arg3
 * esi  arg4
 * edi  arg5
 * ebp  user stack
 * 0(%ebp) arg6
 *
 * This is purely a fast path. For anything complicated we use the int 0x80
 * path below. We set up a complete hardware stack frame to share code
 * with the int 0x80 path.
 */
ENTRY(entry_SYSENTER_compat)
	/* Interrupts are on upon entry. */
	movq	8(%rsp),%r11
	movq	0(%rsp),%rcx
	movq	%rbp,5*8(%rsp)		/* pt_regs->sp */
	cld
	/* jmp	entry_SYSCALL_compat */
ENDPROC(entry_SYSENTER_compat)

/*
 * 32-bit SYSCALL instruction entry.
 *
 * 32-bit SYSCALL saves rip to rcx, clears rflags.RF, then saves rflags to r11,
 * then loads new ss, cs, and rip from previously programmed MSRs.
 * rflags gets masked by a value from another MSR (so CLD and CLAC
 * are not needed). SYSCALL does not save anything on the stack
 * and does not change rsp.
 *
 * Note: rflags saving+masking-with-MSR happens only in Long mode
 * (in legacy 32-bit mode, IF, RF and VM bits are cleared and that's it).
 * Don't get confused: rflags saving+masking depends on Long Mode Active bit
 * (EFER.LMA=1), NOT on bitness of userspace where SYSCALL executes
 * or target CS descriptor's L bit (SYSCALL does not read segment descriptors).
 *
 * Arguments:
 * eax  system call number
 * ecx  return address
 * ebx  arg1
 * ebp  arg2	(note: not saved in the stack frame, should not be touched)
 * edx  arg3
 * esi  arg4
 * edi  arg5
 * esp  user stack
 * 0(%esp) arg6
 */
ENTRY(entry_SYSCALL_compat)
	/* Interrupts are on upon entry. */

	/* Zero-extending 32-bit regs, do not remove */
	movl	%eax, %eax

	/* Construct struct pt_regs on stack */
	movl	$__USER32_DS,6*8(%rsp)	/* pt_regs->ss */
	movl	$__USER32_CS,3*8(%rsp)	/* pt_regs->cs */
	movq	%rax, 8(%rsp)		/* pt_regs->orig_ax */
	movq	%rdi, 0(%rsp)		/* pt_regs->di */
	pushq	%rsi			/* pt_regs->si */
	pushq	%rdx			/* pt_regs->dx */
	pushq	%rbp			/* pt_regs->cx (stashed in bp) */
	pushq	$-ENOSYS		/* pt_regs->ax */
	xorq    %r8,%r8
	pushq   %r8                     /* pt_regs->r8  = 0 */
	pushq   %r8                     /* pt_regs->r9  = 0 */
	pushq   %r8                     /* pt_regs->r10 = 0 */
	pushq   %r8                     /* pt_regs->r11 = 0 */
	pushq   %rbx                    /* pt_regs->rbx */
	pushq   %rbp                    /* pt_regs->rbp (will be overwritten) */
	pushq   %r8                     /* pt_regs->r12 = 0 */
	pushq   %r8                     /* pt_regs->r13 = 0 */
	pushq   %r8                     /* pt_regs->r14 = 0 */
	pushq   %r8                     /* pt_regs->r15 = 0 */

	movq	%rsp, %rdi
	call	do_fast_syscall_32
	jmp	.Lsyscall_32_done
END(entry_SYSCALL_compat)

/*
 * Emulated IA32 system calls via int 0x80.
 *
 * Arguments:
 * eax  system call number
 * ebx  arg1
 * ecx  arg2
 * edx  arg3
 * esi  arg4
 * edi  arg5
 * ebp  arg6	(note: not saved in the stack frame, should not be touched)
 *
 * Notes:
 * Uses the same stack frame as the x86-64 version.
 * All registers except eax must be saved (but ptrace may violate that).
 * Arguments are zero extended. For system calls that want sign extension and
 * take long arguments a wrapper is needed. Most calls can just be called
 * directly.
 * Assumes it is only called from user space and entered with interrupts on.
 */

ENTRY(entry_INT80_compat)
	movq	8(%rsp),%r11
	popq	%rcx

	/*
	 * User tracing code (ptrace or signal handlers) might assume that
	 * the saved RAX contains a 32-bit number when we're invoking a 32-bit
	 * syscall.  Just in case the high bits are nonzero, zero-extend
	 * the syscall number.  (This could almost certainly be deleted
	 * with no ill effects.)
	 */
	movl	%eax, %eax

	/* Construct struct pt_regs on stack (iret frame is already on stack) */
	movq	%rax,(%rsp)		/* pt_regs->orig_ax */
	pushq	%rdi			/* pt_regs->di */
	pushq	%rsi			/* pt_regs->si */
	pushq	%rdx			/* pt_regs->dx */
	pushq	%rcx			/* pt_regs->cx */
	pushq	$-ENOSYS		/* pt_regs->ax */
	xorq    %r8,%r8
	pushq   %r8                     /* pt_regs->r8  = 0 */
	pushq   %r8                     /* pt_regs->r9  = 0 */
	pushq   %r8                     /* pt_regs->r10 = 0 */
	pushq   %r8                     /* pt_regs->r11 = 0 */
	pushq   %rbx                    /* pt_regs->rbx */
	pushq   %rbp                    /* pt_regs->rbp */
	pushq   %r12                    /* pt_regs->r12 */
	pushq   %r13                    /* pt_regs->r13 */
	pushq   %r14                    /* pt_regs->r14 */
	pushq   %r15                    /* pt_regs->r15 */
	cld

	movq	%rsp, %rdi
	call	do_syscall_32_irqs_on
.Lsyscall_32_done:

	/* Go back to user mode. */
	jmp	restore_regs_and_iret
END(entry_INT80_compat)

	ALIGN
GLOBAL(stub32_clone)
	/*
	 * The 32-bit clone ABI is: clone(..., int tls_val, int *child_tidptr).
	 * The 64-bit clone ABI is: clone(..., int *child_tidptr, int tls_val).
	 *
	 * The native 64-bit kernel's sys_clone() implements the latter,
	 * so we need to swap arguments here before calling it:
	 */
	xchg	%r8, %rcx
	jmp	sys_clone
