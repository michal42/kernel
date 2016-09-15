#include <linux/list.h>
#include <linux/spinlock.h>

#include "blktap.h"

static LIST_HEAD(deferred_work_queue);
static DEFINE_SPINLOCK(deferred_work_lock);

void
blktap_run_deferred(void)
{
	LIST_HEAD(queue);
	struct blktap *tap;
	unsigned long flags;

	spin_lock_irqsave(&deferred_work_lock, flags);
	list_splice_init(&deferred_work_queue, &queue);
	spin_unlock_irqrestore(&deferred_work_lock, flags);

	while (!list_empty(&queue)) {
		tap = list_entry(queue.next, struct blktap, deferred_queue);
		spin_lock_irqsave(&deferred_work_lock, flags);
		clear_bit(BLKTAP_DEFERRED, &tap->dev_inuse);
		list_del_init(&tap->deferred_queue);
		spin_unlock_irqrestore(&deferred_work_lock, flags);
		blktap_device_restart(tap);
	}
}

void
blktap_defer(struct blktap *tap)
{
	unsigned long flags;

	spin_lock_irqsave(&deferred_work_lock, flags);
	if (!test_and_set_bit(BLKTAP_DEFERRED, &tap->dev_inuse))
		list_add_tail(&tap->deferred_queue, &deferred_work_queue);
	spin_unlock_irqrestore(&deferred_work_lock, flags);
}
