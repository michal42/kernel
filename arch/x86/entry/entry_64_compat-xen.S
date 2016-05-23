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

/*
 * 32-bit SYSENTER entry.
 *
 * 32-bit system calls through the vDSO's __kernel_vsyscall enter here
 * on 64-bit kernels running on Intel CPUs.
 *
 * The SYSENTER instruction, in principle, should *only* occur in the
 * vDSO.  In practice, a small number of Android devices were shipped
 * with a copy of Bionic that inlined a SYSENTER instruction.  This
 * never happened in any of Google's Bionic versions -- it only happened
 * in a narrow range of Intel-provided versions.
 *
 * SYSENTER loads SS, RSP, CS, and RIP from previously programmed MSRs.
 * IF and VM in RFLAGS are cleared (IOW: interrupts are off).
 * SYSENTER does not save anything on the stack,
 * and does not save old RIP (!!!), RSP, or RFLAGS.
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
 * 32-bit SYSCALL entry.
 *
 * 32-bit system calls through the vDSO's __kernel_vsyscall enter here
 * on 64-bit kernels running on AMD CPUs.
 *
 * The SYSCALL instruction, in principle, should *only* occur in the
 * vDSO.  In practice, it appears that this really is the case.
 * As evidence:
 *
 *  - The calling convention for SYSCALL has changed several times without
 *    anyone noticing.
 *
 *  - Prior to the in-kernel X86_BUG_SYSRET_SS_ATTRS fixup, anything
 *    user task that did SYSCALL without immediately reloading SS
 *    would randomly crash.
 *
 *  - Most programmers do not directly target AMD CPUs, and the 32-bit
 *    SYSCALL instruction does not exist on Intel CPUs.  Even on AMD
 *    CPUs, Linux disables the SYSCALL instruction on 32-bit kernels
 *    because the SYSCALL instruction in legacy/native 32-bit mode (as
 *    opposed to compat mode) is sufficiently poorly designed as to be
 *    essentially unusable.
 *
 * 32-bit SYSCALL saves RIP to RCX, clears RFLAGS.RF, then saves
 * RFLAGS to R11, then loads new SS, CS, and RIP from previously
 * programmed MSRs.  RFLAGS gets masked by a value from another MSR
 * (so CLD and CLAC are not needed).  SYSCALL does not save anything on
 * the stack and does not change RSP.
 *
 * Note: RFLAGS saving+masking-with-MSR happens only in Long mode
 * (in legacy 32-bit mode, IF, RF and VM bits are cleared and that's it).
 * Don't get confused: RFLAGS saving+masking depends on Long Mode Active bit
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
 * 32-bit legacy system call entry.
 *
 * 32-bit x86 Linux system calls traditionally used the INT $0x80
 * instruction.  INT $0x80 lands here.
 *
 * This entry point can be used by 32-bit and 64-bit programs to perform
 * 32-bit system calls.  Instances of INT $0x80 can be found inline in
 * various programs and libraries.  It is also used by the vDSO's
 * __kernel_vsyscall fallback for hardware that doesn't support a faster
 * entry method.  Restarted 32-bit system calls also fall back to INT
 * $0x80 regardless of what instruction was originally used to do the
 * system call.
 *
 * This is considered a slow path.  It is not used by most libc
 * implementations on modern hardware except during process startup.
 *
 * Arguments:
 * eax  system call number
 * ebx  arg1
 * ecx  arg2
 * edx  arg3
 * esi  arg4
 * edi  arg5
 * ebp  arg6
 */
ENTRY(entry_INT80_compat)
	/* Interrupts are on upon entry. */
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
	call	do_int80_syscall_32
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
