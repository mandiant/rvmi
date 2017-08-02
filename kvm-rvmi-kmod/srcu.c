/*
 * Sleepable Read-Copy Update mechanism for mutual exclusion.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) IBM Corporation, 2006
 *
 * Author: Paul McKenney <paulmck@us.ibm.com>
 *
 * For detailed explanation of Read-Copy Update mechanism see -
 * 		Documentation/RCU/ *.txt
 *
 */

#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/percpu.h>
#include <linux/preempt.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/srcu.h>
#include <linux/kthread.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33) && defined(CONFIG_SMP)

/*
 * srcu_readers_active_idx -- returns approximate number of readers
 *	active on the specified rank of per-CPU counters.
 */

static int srcu_readers_active_idx(struct srcu_struct *sp, int idx)
{
	int cpu;
	int sum;

	sum = 0;
	for_each_possible_cpu(cpu)
		sum += per_cpu_ptr(sp->per_cpu_ref, cpu)->c[idx];
	return sum;
}

/*
 * Helper function for synchronize_srcu() and synchronize_srcu_expedited().
 */
static void __synchronize_srcu(struct srcu_struct *sp, void (*sync_func)(void))
{
	int idx;

	idx = sp->completed;
	mutex_lock(&sp->mutex);

	/*
	 * Check to see if someone else did the work for us while we were
	 * waiting to acquire the lock.  We need -two- advances of
	 * the counter, not just one.  If there was but one, we might have
	 * shown up -after- our helper's first synchronize_sched(), thus
	 * having failed to prevent CPU-reordering races with concurrent
	 * srcu_read_unlock()s on other CPUs (see comment below).  So we
	 * either (1) wait for two or (2) supply the second ourselves.
	 */

	if ((sp->completed - idx) >= 2) {
		mutex_unlock(&sp->mutex);
		return;
	}

	sync_func();  /* Force memory barrier on all CPUs. */

	/*
	 * The preceding synchronize_sched() ensures that any CPU that
	 * sees the new value of sp->completed will also see any preceding
	 * changes to data structures made by this CPU.  This prevents
	 * some other CPU from reordering the accesses in its SRCU
	 * read-side critical section to precede the corresponding
	 * srcu_read_lock() -- ensuring that such references will in
	 * fact be protected.
	 *
	 * So it is now safe to do the flip.
	 */

	idx = sp->completed & 0x1;
	sp->completed++;

	sync_func();  /* Force memory barrier on all CPUs. */

	/*
	 * At this point, because of the preceding synchronize_sched(),
	 * all srcu_read_lock() calls using the old counters have completed.
	 * Their corresponding critical sections might well be still
	 * executing, but the srcu_read_lock() primitives themselves
	 * will have finished executing.
	 */

	while (srcu_readers_active_idx(sp, idx))
		schedule_timeout_interruptible(1);

	sync_func();  /* Force memory barrier on all CPUs. */

	/*
	 * The preceding synchronize_sched() forces all srcu_read_unlock()
	 * primitives that were executing concurrently with the preceding
	 * for_each_possible_cpu() loop to have completed by this point.
	 * More importantly, it also forces the corresponding SRCU read-side
	 * critical sections to have also completed, and the corresponding
	 * references to SRCU-protected data items to be dropped.
	 *
	 * Note:
	 *
	 *	Despite what you might think at first glance, the
	 *	preceding synchronize_sched() -must- be within the
	 *	critical section ended by the following mutex_unlock().
	 *	Otherwise, a task taking the early exit can race
	 *	with a srcu_read_unlock(), which might have executed
	 *	just before the preceding srcu_readers_active() check,
	 *	and whose CPU might have reordered the srcu_read_unlock()
	 *	with the preceding critical section.  In this case, there
	 *	is nothing preventing the synchronize_sched() task that is
	 *	taking the early exit from freeing a data structure that
	 *	is still being referenced (out of order) by the task
	 *	doing the srcu_read_unlock().
	 *
	 *	Alternatively, the comparison with "2" on the early exit
	 *	could be changed to "3", but this increases synchronize_srcu()
	 *	latency for bulk loads.  So the current code is preferred.
	 */

	mutex_unlock(&sp->mutex);
}

struct sync_req {
	struct list_head list;
	bool pending;
	bool success;
	struct completion done;
};

static DEFINE_PER_CPU(struct sync_req, sync_req);
static DEFINE_PER_CPU(struct task_struct *, sync_thread);
static DEFINE_MUTEX(rcu_sched_expedited_mutex);

static long synchronize_sched_expedited_count;

static int kvm_rcu_sync_thread(void *data)
{
	int badcpu;
	int cpu = (long)data;
	struct sync_req *req = &per_cpu(sync_req, cpu);

	set_current_state(TASK_INTERRUPTIBLE);
	while (!kthread_should_stop()) {
		if (!req->pending) {
			schedule();
			set_current_state(TASK_INTERRUPTIBLE);
			continue;
		}
		req->pending = false;

		preempt_disable();
		badcpu = smp_processor_id();
		if (likely(cpu == badcpu)) {
			req->success = true;
		} else {
			req->success = false;
			WARN_ONCE(1, "kvm_rcu_sync_thread() on CPU %d, "
				  "expected %d\n", badcpu, cpu);
		}
		preempt_enable();

		complete(&req->done);
	}
	__set_current_state(TASK_RUNNING);

	return 0;
}

static void kvm_synchronize_sched_expedited(void)
{
	int cpu;
	bool need_full_sync = 0;
	struct sync_req *req;
	long snap;
	int trycount = 0;

	smp_mb();  /* ensure prior mod happens before capturing snap. */
	snap = ACCESS_ONCE(synchronize_sched_expedited_count) + 1;
	get_online_cpus();
	while (!mutex_trylock(&rcu_sched_expedited_mutex)) {
		put_online_cpus();
		if (trycount++ < 10)
			udelay(trycount * num_online_cpus());
		else {
			synchronize_sched();
			return;
		}
		if (ACCESS_ONCE(synchronize_sched_expedited_count) - snap > 0) {
			smp_mb(); /* ensure test happens before caller kfree */
			return;
		}
		get_online_cpus();
	}
	for_each_online_cpu(cpu) {
		req = &per_cpu(sync_req, cpu);
		init_completion(&req->done);
		smp_wmb();
		req->pending = true;
		wake_up_process(per_cpu(sync_thread, cpu));
	}
	for_each_online_cpu(cpu) {
		req = &per_cpu(sync_req, cpu);
		wait_for_completion(&req->done);
		if (unlikely(!req->success))
			need_full_sync = 1;
	}
	synchronize_sched_expedited_count++;
	mutex_unlock(&rcu_sched_expedited_mutex);
	put_online_cpus();
	if (need_full_sync)
		synchronize_sched();
}

/**
 * synchronize_srcu_expedited - like synchronize_srcu, but less patient
 * @sp: srcu_struct with which to synchronize.
 *
 * Flip the completed counter, and wait for the old count to drain to zero.
 * As with classic RCU, the updater must use some separate means of
 * synchronizing concurrent updates.  Can block; must be called from
 * process context.
 *
 * Note that it is illegal to call synchronize_srcu_expedited()
 * from the corresponding SRCU read-side critical section; doing so
 * will result in deadlock.  However, it is perfectly legal to call
 * synchronize_srcu_expedited() on one srcu_struct from some other
 * srcu_struct's read-side critical section.
 */
void kvm_synchronize_srcu_expedited(struct srcu_struct *sp)
{
	__synchronize_srcu(sp, kvm_synchronize_sched_expedited);
}
EXPORT_SYMBOL_GPL(kvm_synchronize_srcu_expedited);

static struct sched_param sync_thread_param = {
	.sched_priority = MAX_RT_PRIO-1
};

#ifdef CONFIG_HOTPLUG_CPU
#include <linux/cpumask.h>

static int cpu_callback(struct notifier_block *nfb, unsigned long action,
			void *hcpu)
{
	int hotcpu = (unsigned long)hcpu;
	struct task_struct *p;

	switch (action) {
	case CPU_UP_PREPARE:
	case CPU_UP_PREPARE_FROZEN:
		p = kthread_create(kvm_rcu_sync_thread, hcpu,
				   "kvmsrcusync/%d", hotcpu);
		if (IS_ERR(p)) {
			printk(KERN_ERR "kvm: kvmsrcsync for %d failed\n",
			       hotcpu);
			return NOTIFY_BAD;
		}
		kthread_bind(p, hotcpu);
		sched_setscheduler(p, SCHED_FIFO, &sync_thread_param);
		per_cpu(sync_thread, hotcpu) = p;
		break;
	case CPU_ONLINE:
	case CPU_ONLINE_FROZEN:
		wake_up_process(per_cpu(sync_thread, hotcpu));
		break;
	case CPU_UP_CANCELED:
	case CPU_UP_CANCELED_FROZEN:
		if (!per_cpu(sync_thread, hotcpu))
			break;
		/* Unbind so it can run.  Fall thru. */
		kthread_bind(per_cpu(sync_thread, hotcpu),
			     cpumask_any(cpu_online_mask));
	case CPU_DEAD:
	case CPU_DEAD_FROZEN:
		p = per_cpu(sync_thread, hotcpu);
		per_cpu(sync_thread, hotcpu) = NULL;
		kthread_stop(p);
		break;
	}
	return NOTIFY_OK;
}

static struct notifier_block cpu_nfb = {
	.notifier_call = cpu_callback
};
#endif /* CONFIG_HOTPLUG_CPU */

int kvm_init_srcu(void)
{
	struct task_struct *p;
	int cpu;
	int err;

	get_online_cpus();
	for_each_online_cpu(cpu) {
		p = kthread_create(kvm_rcu_sync_thread, (void *)(long)cpu,
				   "kvmsrcusync/%d", cpu);
		if (IS_ERR(p))
			goto error_out;

		kthread_bind(p, cpu);
		sched_setscheduler(p, SCHED_FIFO, &sync_thread_param);
		per_cpu(sync_thread, cpu) = p;
		wake_up_process(p);
	}
#ifdef CONFIG_HOTPLUG_CPU
	register_cpu_notifier(&cpu_nfb);
#endif /* CONFIG_HOTPLUG_CPU */
	put_online_cpus();

	return 0;

error_out:
	put_online_cpus();
	printk(KERN_ERR "kvm: kvmsrcsync for %d failed\n", cpu);
	err = PTR_ERR(p);
	kvm_exit_srcu();
	return err;
}

void kvm_exit_srcu(void)
{
	int cpu;

#ifdef CONFIG_HOTPLUG_CPU
	unregister_cpu_notifier(&cpu_nfb);
#endif /* CONFIG_HOTPLUG_CPU */
	for_each_online_cpu(cpu)
		if (per_cpu(sync_thread, cpu))
			kthread_stop(per_cpu(sync_thread, cpu));
}

#else

int kvm_init_srcu(void)
{
	return 0;
}

void kvm_exit_srcu(void)
{
}

#endif
