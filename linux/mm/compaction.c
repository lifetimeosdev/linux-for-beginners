// SPDX-License-Identifier: GPL-2.0
/*
 * linux/mm/compaction.c
 *
 * Memory compaction for the reduction of external fragmentation. Note that
 * this heavily depends upon page migration to do all the real heavy
 * lifting
 *
 * Copyright IBM Corp. 2007-2010 Mel Gorman <mel@csn.ul.ie>
 */
#include <linux/cpu.h>
#include <linux/swap.h>
#include <linux/migrate.h>
#include <linux/compaction.h>
#include <linux/mm_inline.h>
#include <linux/sched/signal.h>
#include <linux/backing-dev.h>
#include <linux/sysctl.h>
#include <linux/sysfs.h>
#include <linux/page-isolation.h>
#include <linux/kasan.h>
#include <linux/kthread.h>
#include <linux/freezer.h>
#include <linux/page_owner.h>
#include <linux/psi.h>
#include "internal.h"

#if defined CONFIG_COMPACTION || defined CONFIG_CMA

#define CREATE_TRACE_POINTS
#include <trace/events/compaction.h>

#define block_start_pfn(pfn, order)	round_down(pfn, 1UL << (order))
#define block_end_pfn(pfn, order)	ALIGN((pfn) + 1, 1UL << (order))
#define pageblock_start_pfn(pfn)	block_start_pfn(pfn, pageblock_order)
#define pageblock_end_pfn(pfn)		block_end_pfn(pfn, pageblock_order)

/*
 * Fragmentation score check interval for proactive compaction purposes.
 */
static const unsigned int HPAGE_FRAG_CHECK_INTERVAL_MSEC = 500;

/*
 * Page order with-respect-to which proactive compaction
 * calculates external fragmentation, which is used as
 * the "fragmentation score" of a node/zone.
 */
#if defined CONFIG_TRANSPARENT_HUGEPAGE
#define COMPACTION_HPAGE_ORDER	HPAGE_PMD_ORDER
#elif defined CONFIG_HUGETLBFS
#define COMPACTION_HPAGE_ORDER	HUGETLB_PAGE_ORDER
#else
#define COMPACTION_HPAGE_ORDER	(PMD_SHIFT - PAGE_SHIFT)
#endif

static unsigned long release_freepages(struct list_head *freelist)
{
	struct page *page, *next;
	unsigned long high_pfn = 0;

	list_for_each_entry_safe(page, next, freelist, lru) {
		unsigned long pfn = page_to_pfn(page);
		list_del(&page->lru);
		__free_page(page);
		if (pfn > high_pfn)
			high_pfn = pfn;
	}

	return high_pfn;
}

static void split_map_pages(struct list_head *list)
{
	unsigned int i, order, nr_pages;
	struct page *page, *next;
	LIST_HEAD(tmp_list);

	list_for_each_entry_safe(page, next, list, lru) {
		list_del(&page->lru);

		order = page_private(page);
		nr_pages = 1 << order;

		post_alloc_hook(page, order, __GFP_MOVABLE);
		if (order)
			split_page(page, order);

		for (i = 0; i < nr_pages; i++) {
			list_add(&page->lru, &tmp_list);
			page++;
		}
	}

	list_splice(&tmp_list, list);
}

static inline bool isolation_suitable(struct compact_control *cc,
					struct page *page)
{
	return true;
}

static inline bool pageblock_skip_persistent(struct page *page)
{
	return false;
}

static inline void update_pageblock_skip(struct compact_control *cc,
			struct page *page, unsigned long pfn)
{
}

static void update_cached_migrate(struct compact_control *cc, unsigned long pfn)
{
}

static bool test_and_set_skip(struct compact_control *cc, struct page *page,
							unsigned long pfn)
{
	return false;
}

/*
 * Compaction requires the taking of some coarse locks that are potentially
 * very heavily contended. For async compaction, trylock and record if the
 * lock is contended. The lock will still be acquired but compaction will
 * abort when the current block is finished regardless of success rate.
 * Sync compaction acquires the lock.
 *
 * Always returns true which makes it easier to track lock state in callers.
 */
static bool compact_lock_irqsave(spinlock_t *lock, unsigned long *flags,
						struct compact_control *cc)
	__acquires(lock)
{
	/* Track if the lock is contended in async mode */
	if (cc->mode == MIGRATE_ASYNC && !cc->contended) {
		if (spin_trylock_irqsave(lock, *flags))
			return true;

		cc->contended = true;
	}

	spin_lock_irqsave(lock, *flags);
	return true;
}

/*
 * Compaction requires the taking of some coarse locks that are potentially
 * very heavily contended. The lock should be periodically unlocked to avoid
 * having disabled IRQs for a long time, even when there is nobody waiting on
 * the lock. It might also be that allowing the IRQs will result in
 * need_resched() becoming true. If scheduling is needed, async compaction
 * aborts. Sync compaction schedules.
 * Either compaction type will also abort if a fatal signal is pending.
 * In either case if the lock was locked, it is dropped and not regained.
 *
 * Returns true if compaction should abort due to fatal signal pending, or
 *		async compaction due to need_resched()
 * Returns false when compaction can continue (sync compaction might have
 *		scheduled)
 */
static bool compact_unlock_should_abort(spinlock_t *lock,
		unsigned long flags, bool *locked, struct compact_control *cc)
{
	if (*locked) {
		spin_unlock_irqrestore(lock, flags);
		*locked = false;
	}

	if (fatal_signal_pending(current)) {
		cc->contended = true;
		return true;
	}

	cond_resched();

	return false;
}

/*
 * Isolate free pages onto a private freelist. If @strict is true, will abort
 * returning 0 on any invalid PFNs or non-free pages inside of the pageblock
 * (even though it may still end up isolating some pages).
 */
static unsigned long isolate_freepages_block(struct compact_control *cc,
				unsigned long *start_pfn,
				unsigned long end_pfn,
				struct list_head *freelist,
				unsigned int stride,
				bool strict)
{
	int nr_scanned = 0, total_isolated = 0;
	struct page *cursor;
	unsigned long flags = 0;
	bool locked = false;
	unsigned long blockpfn = *start_pfn;
	unsigned int order;

	/* Strict mode is for isolation, speed is secondary */
	if (strict)
		stride = 1;

	cursor = pfn_to_page(blockpfn);

	/* Isolate free pages. */
	for (; blockpfn < end_pfn; blockpfn += stride, cursor += stride) {
		int isolated;
		struct page *page = cursor;

		/*
		 * Periodically drop the lock (if held) regardless of its
		 * contention, to give chance to IRQs. Abort if fatal signal
		 * pending or async compaction detects need_resched()
		 */
		if (!(blockpfn % SWAP_CLUSTER_MAX)
		    && compact_unlock_should_abort(&cc->zone->lock, flags,
								&locked, cc))
			break;

		nr_scanned++;
		if (!pfn_valid_within(blockpfn))
			goto isolate_fail;

		/*
		 * For compound pages such as THP and hugetlbfs, we can save
		 * potentially a lot of iterations if we skip them at once.
		 * The check is racy, but we can consider only valid values
		 * and the only danger is skipping too much.
		 */
		if (PageCompound(page)) {
			const unsigned int order = compound_order(page);

			if (likely(order < MAX_ORDER)) {
				blockpfn += (1UL << order) - 1;
				cursor += (1UL << order) - 1;
			}
			goto isolate_fail;
		}

		if (!PageBuddy(page))
			goto isolate_fail;

		/*
		 * If we already hold the lock, we can skip some rechecking.
		 * Note that if we hold the lock now, checked_pageblock was
		 * already set in some previous iteration (or strict is true),
		 * so it is correct to skip the suitable migration target
		 * recheck as well.
		 */
		if (!locked) {
			locked = compact_lock_irqsave(&cc->zone->lock,
								&flags, cc);

			/* Recheck this is a buddy page under lock */
			if (!PageBuddy(page))
				goto isolate_fail;
		}

		/* Found a free page, will break it into order-0 pages */
		order = buddy_order(page);
		isolated = __isolate_free_page(page, order);
		if (!isolated)
			break;
		set_page_private(page, order);

		total_isolated += isolated;
		cc->nr_freepages += isolated;
		list_add_tail(&page->lru, freelist);

		if (!strict && cc->nr_migratepages <= cc->nr_freepages) {
			blockpfn += isolated;
			break;
		}
		/* Advance to the end of split page */
		blockpfn += isolated - 1;
		cursor += isolated - 1;
		continue;

isolate_fail:
		if (strict)
			break;
		else
			continue;

	}

	if (locked)
		spin_unlock_irqrestore(&cc->zone->lock, flags);

	/*
	 * There is a tiny chance that we have read bogus compound_order(),
	 * so be careful to not go outside of the pageblock.
	 */
	if (unlikely(blockpfn > end_pfn))
		blockpfn = end_pfn;

	/* Record how far we have got within the block */
	*start_pfn = blockpfn;

	/*
	 * If strict isolation is requested by CMA then check that all the
	 * pages requested were isolated. If there were any failures, 0 is
	 * returned and CMA will fail.
	 */
	if (strict && blockpfn < end_pfn)
		total_isolated = 0;

	cc->total_free_scanned += nr_scanned;
	return total_isolated;
}

/**
 * isolate_freepages_range() - isolate free pages.
 * @cc:        Compaction control structure.
 * @start_pfn: The first PFN to start isolating.
 * @end_pfn:   The one-past-last PFN.
 *
 * Non-free pages, invalid PFNs, or zone boundaries within the
 * [start_pfn, end_pfn) range are considered errors, cause function to
 * undo its actions and return zero.
 *
 * Otherwise, function returns one-past-the-last PFN of isolated page
 * (which may be greater then end_pfn if end fell in a middle of
 * a free page).
 */
unsigned long
isolate_freepages_range(struct compact_control *cc,
			unsigned long start_pfn, unsigned long end_pfn)
{
	unsigned long isolated, pfn, block_start_pfn, block_end_pfn;
	LIST_HEAD(freelist);

	pfn = start_pfn;
	block_start_pfn = pageblock_start_pfn(pfn);
	if (block_start_pfn < cc->zone->zone_start_pfn)
		block_start_pfn = cc->zone->zone_start_pfn;
	block_end_pfn = pageblock_end_pfn(pfn);

	for (; pfn < end_pfn; pfn += isolated,
				block_start_pfn = block_end_pfn,
				block_end_pfn += pageblock_nr_pages) {
		/* Protect pfn from changing by isolate_freepages_block */
		unsigned long isolate_start_pfn = pfn;

		block_end_pfn = min(block_end_pfn, end_pfn);

		/*
		 * pfn could pass the block_end_pfn if isolated freepage
		 * is more than pageblock order. In this case, we adjust
		 * scanning range to right one.
		 */
		if (pfn >= block_end_pfn) {
			block_start_pfn = pageblock_start_pfn(pfn);
			block_end_pfn = pageblock_end_pfn(pfn);
			block_end_pfn = min(block_end_pfn, end_pfn);
		}

		if (!pageblock_pfn_to_page(block_start_pfn,
					block_end_pfn, cc->zone))
			break;

		isolated = isolate_freepages_block(cc, &isolate_start_pfn,
					block_end_pfn, &freelist, 0, true);

		/*
		 * In strict mode, isolate_freepages_block() returns 0 if
		 * there are any holes in the block (ie. invalid PFNs or
		 * non-free pages).
		 */
		if (!isolated)
			break;

		/*
		 * If we managed to isolate pages, it is always (1 << n) *
		 * pageblock_nr_pages for some non-negative n.  (Max order
		 * page may span two pageblocks).
		 */
	}

	/* __isolate_free_page() does not map the pages */
	split_map_pages(&freelist);

	if (pfn < end_pfn) {
		/* Loop terminated early, cleanup. */
		release_freepages(&freelist);
		return 0;
	}

	/* We don't use freelists for anything. */
	return pfn;
}

/* Similar to reclaim, but different enough that they don't share logic */
static bool too_many_isolated(pg_data_t *pgdat)
{
	unsigned long active, inactive, isolated;

	inactive = node_page_state(pgdat, NR_INACTIVE_FILE) +
			node_page_state(pgdat, NR_INACTIVE_ANON);
	active = node_page_state(pgdat, NR_ACTIVE_FILE) +
			node_page_state(pgdat, NR_ACTIVE_ANON);
	isolated = node_page_state(pgdat, NR_ISOLATED_FILE) +
			node_page_state(pgdat, NR_ISOLATED_ANON);

	return isolated > (inactive + active) / 2;
}

/**
 * isolate_migratepages_block() - isolate all migrate-able pages within
 *				  a single pageblock
 * @cc:		Compaction control structure.
 * @low_pfn:	The first PFN to isolate
 * @end_pfn:	The one-past-the-last PFN to isolate, within same pageblock
 * @isolate_mode: Isolation mode to be used.
 *
 * Isolate all pages that can be migrated from the range specified by
 * [low_pfn, end_pfn). The range is expected to be within same pageblock.
 * Returns zero if there is a fatal signal pending, otherwise PFN of the
 * first page that was not scanned (which may be both less, equal to or more
 * than end_pfn).
 *
 * The pages are isolated on cc->migratepages list (not required to be empty),
 * and cc->nr_migratepages is updated accordingly. The cc->migrate_pfn field
 * is neither read nor updated.
 */
static unsigned long
isolate_migratepages_block(struct compact_control *cc, unsigned long low_pfn,
			unsigned long end_pfn, isolate_mode_t isolate_mode)
{
	pg_data_t *pgdat = cc->zone->zone_pgdat;
	unsigned long nr_scanned = 0, nr_isolated = 0;
	struct lruvec *lruvec;
	unsigned long flags = 0;
	bool locked = false;
	struct page *page = NULL, *valid_page = NULL;
	bool skip_on_failure = false;
	unsigned long next_skip_pfn = 0;
	bool skip_updated = false;

	/*
	 * Ensure that there are not too many pages isolated from the LRU
	 * list by either parallel reclaimers or compaction. If there are,
	 * delay for some time until fewer pages are isolated
	 */
	while (unlikely(too_many_isolated(pgdat))) {
		/* stop isolation if there are still pages not migrated */
		if (cc->nr_migratepages)
			return 0;

		/* async migration should just abort */
		if (cc->mode == MIGRATE_ASYNC)
			return 0;

		congestion_wait(BLK_RW_ASYNC, HZ/10);

		if (fatal_signal_pending(current))
			return 0;
	}

	cond_resched();

	if (cc->direct_compaction && (cc->mode == MIGRATE_ASYNC)) {
		skip_on_failure = true;
		next_skip_pfn = block_end_pfn(low_pfn, cc->order);
	}

	/* Time to isolate some pages for migration */
	for (; low_pfn < end_pfn; low_pfn++) {

		if (skip_on_failure && low_pfn >= next_skip_pfn) {
			/*
			 * We have isolated all migration candidates in the
			 * previous order-aligned block, and did not skip it due
			 * to failure. We should migrate the pages now and
			 * hopefully succeed compaction.
			 */
			if (nr_isolated)
				break;

			/*
			 * We failed to isolate in the previous order-aligned
			 * block. Set the new boundary to the end of the
			 * current block. Note we can't simply increase
			 * next_skip_pfn by 1 << order, as low_pfn might have
			 * been incremented by a higher number due to skipping
			 * a compound or a high-order buddy page in the
			 * previous loop iteration.
			 */
			next_skip_pfn = block_end_pfn(low_pfn, cc->order);
		}

		/*
		 * Periodically drop the lock (if held) regardless of its
		 * contention, to give chance to IRQs. Abort completely if
		 * a fatal signal is pending.
		 */
		if (!(low_pfn % SWAP_CLUSTER_MAX)
		    && compact_unlock_should_abort(&pgdat->lru_lock,
					    flags, &locked, cc)) {
			low_pfn = 0;
			goto fatal_pending;
		}

		if (!pfn_valid_within(low_pfn))
			goto isolate_fail;
		nr_scanned++;

		page = pfn_to_page(low_pfn);

		/*
		 * Check if the pageblock has already been marked skipped.
		 * Only the aligned PFN is checked as the caller isolates
		 * COMPACT_CLUSTER_MAX at a time so the second call must
		 * not falsely conclude that the block should be skipped.
		 */
		if (!valid_page && IS_ALIGNED(low_pfn, pageblock_nr_pages)) {
			if (!cc->ignore_skip_hint && get_pageblock_skip(page)) {
				low_pfn = end_pfn;
				goto isolate_abort;
			}
			valid_page = page;
		}

		/*
		 * Skip if free. We read page order here without zone lock
		 * which is generally unsafe, but the race window is small and
		 * the worst thing that can happen is that we skip some
		 * potential isolation targets.
		 */
		if (PageBuddy(page)) {
			unsigned long freepage_order = buddy_order_unsafe(page);

			/*
			 * Without lock, we cannot be sure that what we got is
			 * a valid page order. Consider only values in the
			 * valid order range to prevent low_pfn overflow.
			 */
			if (freepage_order > 0 && freepage_order < MAX_ORDER)
				low_pfn += (1UL << freepage_order) - 1;
			continue;
		}

		/*
		 * Regardless of being on LRU, compound pages such as THP and
		 * hugetlbfs are not to be compacted unless we are attempting
		 * an allocation much larger than the huge page size (eg CMA).
		 * We can potentially save a lot of iterations if we skip them
		 * at once. The check is racy, but we can consider only valid
		 * values and the only danger is skipping too much.
		 */
		if (PageCompound(page) && !cc->alloc_contig) {
			const unsigned int order = compound_order(page);

			if (likely(order < MAX_ORDER))
				low_pfn += (1UL << order) - 1;
			goto isolate_fail;
		}

		/*
		 * Check may be lockless but that's ok as we recheck later.
		 * It's possible to migrate LRU and non-lru movable pages.
		 * Skip any other type of page
		 */
		if (!PageLRU(page)) {
			/*
			 * __PageMovable can return false positive so we need
			 * to verify it under page_lock.
			 */
			if (unlikely(__PageMovable(page)) &&
					!PageIsolated(page)) {
				if (locked) {
					spin_unlock_irqrestore(&pgdat->lru_lock,
									flags);
					locked = false;
				}

				if (!isolate_movable_page(page, isolate_mode))
					goto isolate_success;
			}

			goto isolate_fail;
		}

		/*
		 * Migration will fail if an anonymous page is pinned in memory,
		 * so avoid taking lru_lock and isolating it unnecessarily in an
		 * admittedly racy check.
		 */
		if (!page_mapping(page) &&
		    page_count(page) > page_mapcount(page))
			goto isolate_fail;

		/*
		 * Only allow to migrate anonymous pages in GFP_NOFS context
		 * because those do not depend on fs locks.
		 */
		if (!(cc->gfp_mask & __GFP_FS) && page_mapping(page))
			goto isolate_fail;

		/* If we already hold the lock, we can skip some rechecking */
		if (!locked) {
			locked = compact_lock_irqsave(&pgdat->lru_lock,
								&flags, cc);

			/* Try get exclusive access under lock */
			if (!skip_updated) {
				skip_updated = true;
				if (test_and_set_skip(cc, page, low_pfn))
					goto isolate_abort;
			}

			/* Recheck PageLRU and PageCompound under lock */
			if (!PageLRU(page))
				goto isolate_fail;

			/*
			 * Page become compound since the non-locked check,
			 * and it's on LRU. It can only be a THP so the order
			 * is safe to read and it's 0 for tail pages.
			 */
			if (unlikely(PageCompound(page) && !cc->alloc_contig)) {
				low_pfn += compound_nr(page) - 1;
				goto isolate_fail;
			}
		}

		lruvec = mem_cgroup_page_lruvec(page, pgdat);

		/* Try isolate the page */
		if (__isolate_lru_page(page, isolate_mode) != 0)
			goto isolate_fail;

		/* The whole page is taken off the LRU; skip the tail pages. */
		if (PageCompound(page))
			low_pfn += compound_nr(page) - 1;

		/* Successfully isolated */
		del_page_from_lru_list(page, lruvec, page_lru(page));
		mod_node_page_state(page_pgdat(page),
				NR_ISOLATED_ANON + page_is_file_lru(page),
				thp_nr_pages(page));

isolate_success:
		list_add(&page->lru, &cc->migratepages);
		cc->nr_migratepages += compound_nr(page);
		nr_isolated += compound_nr(page);

		/*
		 * Avoid isolating too much unless this block is being
		 * rescanned (e.g. dirty/writeback pages, parallel allocation)
		 * or a lock is contended. For contention, isolate quickly to
		 * potentially remove one source of contention.
		 */
		if (cc->nr_migratepages >= COMPACT_CLUSTER_MAX &&
		    !cc->rescan && !cc->contended) {
			++low_pfn;
			break;
		}

		continue;
isolate_fail:
		if (!skip_on_failure)
			continue;

		/*
		 * We have isolated some pages, but then failed. Release them
		 * instead of migrating, as we cannot form the cc->order buddy
		 * page anyway.
		 */
		if (nr_isolated) {
			if (locked) {
				spin_unlock_irqrestore(&pgdat->lru_lock, flags);
				locked = false;
			}
			putback_movable_pages(&cc->migratepages);
			cc->nr_migratepages = 0;
			nr_isolated = 0;
		}

		if (low_pfn < next_skip_pfn) {
			low_pfn = next_skip_pfn - 1;
			/*
			 * The check near the loop beginning would have updated
			 * next_skip_pfn too, but this is a bit simpler.
			 */
			next_skip_pfn += 1UL << cc->order;
		}
	}

	/*
	 * The PageBuddy() check could have potentially brought us outside
	 * the range to be scanned.
	 */
	if (unlikely(low_pfn > end_pfn))
		low_pfn = end_pfn;

isolate_abort:
	if (locked)
		spin_unlock_irqrestore(&pgdat->lru_lock, flags);

	/*
	 * Updated the cached scanner pfn once the pageblock has been scanned
	 * Pages will either be migrated in which case there is no point
	 * scanning in the near future or migration failed in which case the
	 * failure reason may persist. The block is marked for skipping if
	 * there were no pages isolated in the block or if the block is
	 * rescanned twice in a row.
	 */
	if (low_pfn == end_pfn && (!nr_isolated || cc->rescan)) {
		if (valid_page && !skip_updated)
			set_pageblock_skip(valid_page);
		update_cached_migrate(cc, low_pfn);
	}

fatal_pending:
	cc->total_migrate_scanned += nr_scanned;

	return low_pfn;
}

/**
 * isolate_migratepages_range() - isolate migrate-able pages in a PFN range
 * @cc:        Compaction control structure.
 * @start_pfn: The first PFN to start isolating.
 * @end_pfn:   The one-past-last PFN.
 *
 * Returns zero if isolation fails fatally due to e.g. pending signal.
 * Otherwise, function returns one-past-the-last PFN of isolated page
 * (which may be greater than end_pfn if end fell in a middle of a THP page).
 */
unsigned long
isolate_migratepages_range(struct compact_control *cc, unsigned long start_pfn,
							unsigned long end_pfn)
{
	unsigned long pfn, block_start_pfn, block_end_pfn;

	/* Scan block by block. First and last block may be incomplete */
	pfn = start_pfn;
	block_start_pfn = pageblock_start_pfn(pfn);
	if (block_start_pfn < cc->zone->zone_start_pfn)
		block_start_pfn = cc->zone->zone_start_pfn;
	block_end_pfn = pageblock_end_pfn(pfn);

	for (; pfn < end_pfn; pfn = block_end_pfn,
				block_start_pfn = block_end_pfn,
				block_end_pfn += pageblock_nr_pages) {

		block_end_pfn = min(block_end_pfn, end_pfn);

		if (!pageblock_pfn_to_page(block_start_pfn,
					block_end_pfn, cc->zone))
			continue;

		pfn = isolate_migratepages_block(cc, pfn, block_end_pfn,
							ISOLATE_UNEVICTABLE);

		if (!pfn)
			break;

		if (cc->nr_migratepages >= COMPACT_CLUSTER_MAX)
			break;
	}

	return pfn;
}

#endif /* CONFIG_COMPACTION || CONFIG_CMA */