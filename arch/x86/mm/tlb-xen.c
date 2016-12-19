#include <linux/init.h>
#include <linux/mm.h>
#include <linux/spinlock.h>
#include <linux/smp.h>
#include <linux/cpumask.h>

#include <asm/tlbflush.h>
#include <asm/mmu_context.h>
#include <asm/cache.h>
#include <linux/debugfs.h>

void switch_mm(struct mm_struct *prev, struct mm_struct *next,
	       struct task_struct *tsk)
{
	unsigned long flags;

	local_irq_save(flags);
	switch_mm_irqs_off(prev, next, tsk);
	local_irq_restore(flags);
}

void switch_mm_irqs_off(struct mm_struct *prev, struct mm_struct *next,
			struct task_struct *tsk)
{
	unsigned cpu = smp_processor_id();
	struct mmuext_op _op[2 + (sizeof(long) > 4)], *op = _op;

	if (likely(prev != next)) {
#ifdef CONFIG_X86_64_XEN
		pgd_t *upgd;
#endif

		BUG_ON(!xen_feature(XENFEAT_writable_page_tables) &&
		       !PagePinned(virt_to_page(next->pgd)));

		if (IS_ENABLED(CONFIG_VMAP_STACK)) {
			/*
			 * If our current stack is in vmalloc space and isn't
			 * mapped in the new pgd, we'll double-fault.  Forcibly
			 * map it.
			 */
			unsigned int stack_pgd_index = pgd_index(current_stack_pointer());

			pgd_t *pgd = next->pgd + stack_pgd_index;

			if (unlikely(pgd_none(*pgd)))
				set_pgd(pgd, init_mm.pgd[stack_pgd_index]);
		}

#if defined(CONFIG_SMP) && !defined(CONFIG_XEN) /* XEN: no lazy tlb */
		this_cpu_write(cpu_tlbstate.state, TLBSTATE_OK);
		this_cpu_write(cpu_tlbstate.active_mm, next);
#endif

		cpumask_set_cpu(cpu, mm_cpumask(next));

		/*
		 * Re-load page tables: load_cr3(next->pgd).
		 *
		 * This logic has an ordering constraint:
		 *
		 *  CPU 0: Write to a PTE for 'next'
		 *  CPU 0: load bit 1 in mm_cpumask.  if nonzero, send IPI.
		 *  CPU 1: set bit 1 in next's mm_cpumask
		 *  CPU 1: load from the PTE that CPU 0 writes (implicit)
		 *
		 * We need to prevent an outcome in which CPU 1 observes
		 * the new PTE value and CPU 0 observes bit 1 clear in
		 * mm_cpumask.  (If that occurs, then the IPI will never
		 * be sent, and CPU 0's TLB will contain a stale entry.)
		 *
		 * The bad outcome can occur if either CPU's load is
		 * reordered before that CPU's store, so both CPUs must
		 * execute full barriers to prevent this from happening.
		 *
		 * Thus, switch_mm needs a full barrier between the
		 * store to mm_cpumask and any operation that could load
		 * from next->pgd.  TLB fills are special and can happen
		 * due to instruction fetches or for no reason at all,
		 * and neither LOCK nor MFENCE orders them.
		 * Fortunately, load_cr3() is serializing and gives the
		 * ordering guarantee we need.
		 *
		 */
		op->cmd = MMUEXT_NEW_BASEPTR;
		op->arg1.mfn = virt_to_mfn(next->pgd);
		op++;

		trace_tlb_flush(TLB_FLUSH_ON_TASK_SWITCH, TLB_FLUSH_ALL);

#ifdef CONFIG_X86_64_XEN
		/* xen_new_user_pt(next->pgd) */
		op->cmd = MMUEXT_NEW_USER_BASEPTR;
		upgd = __user_pgd(next->pgd);
		op->arg1.mfn = likely(upgd) ? virt_to_mfn(upgd) : 0;
		op++;
#endif

		/* Load per-mm CR4 state */
		load_mm_cr4(next);

#ifdef CONFIG_MODIFY_LDT_SYSCALL
		/*
		 * Load the LDT, if the LDT is different.
		 *
		 * It's possible that prev->context.ldt doesn't match
		 * the LDT register.  This can happen if leave_mm(prev)
		 * was called and then modify_ldt changed
		 * prev->context.ldt but suppressed an IPI to this CPU.
		 * In this case, prev->context.ldt != NULL, because we
		 * never set context.ldt to NULL while the mm still
		 * exists.  That means that next->context.ldt !=
		 * prev->context.ldt, because mms never share an LDT.
		 */
		if (unlikely(prev->context.ldt != next->context.ldt)) {
			/* load_mm_ldt(next) */
			const struct ldt_struct *ldt;

			/* lockless_dereference synchronizes with smp_store_release */
			ldt = lockless_dereference(next->context.ldt);
			op->cmd = MMUEXT_SET_LDT;
			if (unlikely(ldt)) {
				op->arg1.linear_addr = (long)ldt->entries;
				op->arg2.nr_ents     = ldt->size;
			} else {
				op->arg1.linear_addr = 0;
				op->arg2.nr_ents     = 0;
			}
			op++;
		}
#endif

		BUG_ON(HYPERVISOR_mmuext_op(_op, op-_op, NULL, DOMID_SELF));

		/* Stop TLB flushes for the previous mm */
		cpumask_clear_cpu(cpu, mm_cpumask(prev));
	}
#if defined(CONFIG_SMP) && !defined(CONFIG_XEN) /* XEN: no lazy tlb */
	  else {
		this_cpu_write(cpu_tlbstate.state, TLBSTATE_OK);
		BUG_ON(this_cpu_read(cpu_tlbstate.active_mm) != next);

		if (!cpumask_test_cpu(cpu, mm_cpumask(next))) {
			/*
			 * On established mms, the mm_cpumask is only changed
			 * from irq context, from ptep_clear_flush() while in
			 * lazy tlb mode, and here. Irqs are blocked during
			 * schedule, protecting us from simultaneous changes.
			 */
			cpumask_set_cpu(cpu, mm_cpumask(next));

			/*
			 * We were in lazy tlb mode and leave_mm disabled
			 * tlb flush IPI delivery. We must reload CR3
			 * to make sure to use no freed page tables.
			 *
			 * As above, load_cr3() is serializing and orders TLB
			 * fills with respect to the mm_cpumask write.
			 */
			load_cr3(next->pgd);
			trace_tlb_flush(TLB_FLUSH_ON_TASK_SWITCH, TLB_FLUSH_ALL);
			load_mm_cr4(next);
			xen_new_user_pt(next->pgd);
			load_mm_ldt(next);
		}
	}
#endif
}

#ifdef CONFIG_SMP

void flush_tlb_others(const struct cpumask *cpumask, struct mm_struct *mm,
		      unsigned long start, unsigned long end)
{
	count_vm_tlb_event(NR_TLB_REMOTE_FLUSH);
	if (end == TLB_FLUSH_ALL) {
		xen_tlb_flush_mask(cpumask);
		trace_tlb_flush(TLB_REMOTE_SHOOTDOWN, TLB_FLUSH_ALL);
	} else {
		/* flush range by one by one 'invlpg' */
		unsigned long addr;

		for (addr = start; addr < end; addr += PAGE_SIZE)
			xen_invlpg_mask(cpumask, addr);
		trace_tlb_flush(TLB_REMOTE_SHOOTDOWN, PFN_DOWN(end - start));
	}
}

/*
 * See Documentation/x86/tlb.txt for details.  We choose 33
 * because it is large enough to cover the vast majority (at
 * least 95%) of allocations, and is small enough that we are
 * confident it will not cause too much overhead.  Each single
 * flush is about 100 ns, so this caps the maximum overhead at
 * _about_ 3,000 ns.
 *
 * This is in units of pages.
 */
static unsigned long tlb_single_page_flush_ceiling __read_mostly = 33;

void flush_tlb_mm_range(struct mm_struct *mm, unsigned long start,
				unsigned long end, unsigned long vmflag)
{
	unsigned long addr;
	/* do a global flush by default */
	unsigned long base_pages_to_flush = TLB_FLUSH_ALL;
	const cpumask_t *mask = mm_cpumask(mm);
	cpumask_var_t temp;

	preempt_disable();
	if (current->active_mm != mm || !current->mm) {
		/* Synchronize with switch_mm. */
		smp_mb();

		if (cpumask_any_but(mask, smp_processor_id()) >= nr_cpu_ids) {
			preempt_enable();
			return;
		}
		if (alloc_cpumask_var(&temp, GFP_ATOMIC)) {
			cpumask_andnot(temp, mask,
				       cpumask_of(smp_processor_id()));
			mask = temp;
		}
	}

	if ((end != TLB_FLUSH_ALL) && !(vmflag & VM_HUGETLB))
		base_pages_to_flush = (end - start) >> PAGE_SHIFT;

	/*
	 * Both branches below are implicit full barriers (MOV to CR or
	 * INVLPG) that synchronize with switch_mm.
	 */
	if (base_pages_to_flush > tlb_single_page_flush_ceiling) {
		base_pages_to_flush = TLB_FLUSH_ALL;
		count_vm_tlb_event(NR_TLB_LOCAL_FLUSH_ALL);
		xen_tlb_flush_mask(mask);
	} else {
		/* flush range by one by one 'invlpg' */
		for (addr = start; addr < end; addr += PAGE_SIZE) {
			count_vm_tlb_event(NR_TLB_LOCAL_FLUSH_ONE);
			xen_invlpg_mask(mask, addr);
		}
	}
	trace_tlb_flush(TLB_LOCAL_MM_SHOOTDOWN, base_pages_to_flush);
	if (mask != mm_cpumask(mm))
		free_cpumask_var(temp);
	preempt_enable();
}

void flush_tlb_kernel_range(unsigned long start, unsigned long end)
{

	/* Balance as user space task's flush, a bit conservative */
	if (end == TLB_FLUSH_ALL ||
	    (end - start) > tlb_single_page_flush_ceiling * PAGE_SIZE) {
		xen_tlb_flush_all();
	} else {
		unsigned long addr;

		/* flush range by one by one 'invlpg' */
		for (addr = start; addr < end; addr += PAGE_SIZE)
			xen_invlpg_all(addr);
	}
}

static ssize_t tlbflush_read_file(struct file *file, char __user *user_buf,
			     size_t count, loff_t *ppos)
{
	char buf[32];
	unsigned int len;

	len = sprintf(buf, "%ld\n", tlb_single_page_flush_ceiling);
	return simple_read_from_buffer(user_buf, count, ppos, buf, len);
}

static ssize_t tlbflush_write_file(struct file *file,
		 const char __user *user_buf, size_t count, loff_t *ppos)
{
	char buf[32];
	ssize_t len;
	int ceiling;

	len = min(count, sizeof(buf) - 1);
	if (copy_from_user(buf, user_buf, len))
		return -EFAULT;

	buf[len] = '\0';
	if (kstrtoint(buf, 0, &ceiling))
		return -EINVAL;

	if (ceiling < 0)
		return -EINVAL;

	tlb_single_page_flush_ceiling = ceiling;
	return count;
}

static const struct file_operations fops_tlbflush = {
	.read = tlbflush_read_file,
	.write = tlbflush_write_file,
	.llseek = default_llseek,
};

static int __init create_tlb_single_page_flush_ceiling(void)
{
	debugfs_create_file("tlb_single_page_flush_ceiling", S_IRUSR | S_IWUSR,
			    arch_debugfs_dir, NULL, &fops_tlbflush);
	return 0;
}
late_initcall(create_tlb_single_page_flush_ceiling);

#endif /* CONFIG_SMP */
