// SPDX-License-Identifier: GPL-2.0+
/*
 * Procedures for maintaining information about logical memory blocks.
 *
 * Peter Bergner, IBM Corp.	June 2001.
 * Copyright (C) 2001 Peter Bergner.
 */

#include <event.h>
#include <image.h>
#include <mapmem.h>
#include <lmb.h>
#include <log.h>
#include <malloc.h>
#include <spl.h>

#include <asm/global_data.h>
#include <asm/sections.h>
#include <linux/kernel.h>
#include <linux/list_sort.h>
#include <linux/sizes.h>

DECLARE_GLOBAL_DATA_PTR;

#define MAP_OP_RESERVE		(u8)0x1
#define MAP_OP_FREE		(u8)0x2
#define MAP_OP_ADD		(u8)0x3

#define LMB_ALLOC_ANYWHERE	0

static LIST_HEAD(lmb_free_mem);
static LIST_HEAD(lmb_used_mem);

extern bool is_addr_in_ram(uintptr_t addr);

static bool lmb_notify(enum lmb_flags flags)
{
	return !(flags & LMB_NONOTIFY);
}

static void lmb_map_update_notify(phys_addr_t addr, phys_size_t size,
				  u8 op)
{
	struct event_lmb_map_update lmb_map = {0};

	lmb_map.base = addr;
	lmb_map.size = size;
	lmb_map.op = op;

	if (is_addr_in_ram((uintptr_t)addr))
		event_notify(EVT_LMB_MAP_UPDATE, &lmb_map, sizeof(lmb_map));
}

static void lmb_dump_region(struct list_head *lmb_rgn_lst, char *name)
{
	unsigned int i;
	struct lmb_region *rgn;
	struct lmb_rgn_node *rgn_node;
	unsigned long long base, size, end;
	enum lmb_flags flags;

	printf(" %s.count = 0x%zx\n", name, list_count_nodes(lmb_rgn_lst));

	i = 0;
	list_for_each_entry(rgn_node, lmb_rgn_lst, link) {
		rgn = &rgn_node->rgn;

		base = rgn->base;
		size = rgn->size;
		end = base + size - 1;
		flags = rgn->flags;

		printf(" %s[%d]\t[0x%llx-0x%llx], 0x%08llx bytes flags: %x\n",
		       name, i++, base, end, size, flags);
	}
}

void lmb_dump_all_force(void)
{
	printf("lmb_dump_all:\n");
	lmb_dump_region(&lmb_free_mem, "memory");
	lmb_dump_region(&lmb_used_mem, "reserved");
}

void lmb_dump_all(void)
{
#ifdef DEBUG
	lmb_dump_all_force();
#endif
}

/**
 * lmb_mem_cmp() - comparator function for sorting memory map
 *
 * Sorts the memory list from lowest address to highest address
 *
 * @priv:	unused
 * @a:		first memory area
 * @b:		second memory area
 * Return:	-1 if @a is before @b, 1 if @b is before @a, 0 if equal
 */
static int lmb_mem_cmp(void *priv, struct list_head *a, struct list_head *b)
{
	struct lmb_rgn_node *mema = list_entry(a, struct lmb_rgn_node, link);
	struct lmb_rgn_node *memb = list_entry(b, struct lmb_rgn_node, link);

	if (mema->rgn.base == memb->rgn.base)
		return 0;
	else if (mema->rgn.base < memb->rgn.base)
		return -1;
	else
		return 1;
}

static void lmb_merge_adjacents(struct list_head *lmb_rgn_lst)
{
	struct lmb_rgn_node *cur_node;
	struct lmb_rgn_node *prev_node = NULL;
	bool merge_again = true;

	/* merge entries that can be merged */
	while (merge_again) {
		merge_again = false;
		list_for_each_entry(cur_node, lmb_rgn_lst, link) {
			struct lmb_region *prev;
			struct lmb_region *cur;
			phys_size_t size;

			if (!prev_node) {
				prev_node = cur_node;
				continue;
			}

			cur = &cur_node->rgn;
			prev = &prev_node->rgn;

			if ((cur->base + cur->size == prev->base) &&
			    (prev->flags == cur->flags)) {
				/* There is an existing map before, reuse it */
				size = cur->size;
				prev->size += size;
				prev->base -= size;
				list_del(&cur_node->link);
				free(cur_node);

				merge_again = true;
				break;
			}

			prev_node = cur_node;
		}
	}
}

static void lmb_list_sort(struct list_head *lmb_rgn_lst)
{
	list_sort(NULL, lmb_rgn_lst, lmb_mem_cmp);

	lmb_merge_adjacents(lmb_rgn_lst);
}

static long lmb_addrs_overlap(phys_addr_t base1, phys_size_t size1,
			      phys_addr_t base2, phys_size_t size2)
{
	const phys_addr_t base1_end = base1 + size1 - 1;
	const phys_addr_t base2_end = base2 + size2 - 1;

	return ((base1 <= base2_end) && (base2 <= base1_end));
}

static long lmb_addrs_adjacent(phys_addr_t base1, phys_size_t size1,
			       phys_addr_t base2, phys_size_t size2)
{
	if (base2 == base1 + size1)
		return 1;
	else if (base1 == base2 + size2)
		return -1;

	return 0;
}

void arch_lmb_reserve_generic(ulong sp, ulong end, ulong align)
{
	ulong bank_end;
	int bank;

	/*
	 * Reserve memory from aligned address below the bottom of U-Boot stack
	 * until end of U-Boot area using LMB to prevent U-Boot from overwriting
	 * that memory.
	 */
	debug("## Current stack ends at 0x%08lx ", sp);

	/* adjust sp by 4K to be safe */
	sp -= align;
	for (bank = 0; bank < CONFIG_NR_DRAM_BANKS; bank++) {
		if (!gd->bd->bi_dram[bank].size ||
		    sp < gd->bd->bi_dram[bank].start)
			continue;
		/* Watch out for RAM at end of address space! */
		bank_end = gd->bd->bi_dram[bank].start +
			gd->bd->bi_dram[bank].size - 1;
		if (sp > bank_end)
			continue;
		if (bank_end > end)
			bank_end = end - 1;

		lmb_reserve(sp, bank_end - sp + 1, LMB_NOOVERWRITE);

		if (gd->flags & GD_FLG_SKIP_RELOC)
			lmb_reserve((phys_addr_t)(uintptr_t)_start, gd->mon_len,
				    LMB_NOOVERWRITE);

		break;
	}
}

static void lmb_reserve_common(void *fdt_blob)
{
	arch_lmb_reserve();
	board_lmb_reserve();

	if (CONFIG_IS_ENABLED(OF_LIBFDT) && fdt_blob)
		boot_fdt_add_mem_rsv_regions(fdt_blob);
}

static __maybe_unused void lmb_reserve_common_spl(void)
{
	phys_addr_t rsv_start;
	phys_size_t rsv_size;

	/*
	 * Assume a SPL stack of 16KB. This must be
	 * more than enough for the SPL stage.
	 */
	if (IS_ENABLED(CONFIG_SPL_STACK_R_ADDR)) {
		rsv_start = gd->start_addr_sp - 16384;
		rsv_size = 16384;
		lmb_reserve(rsv_start, rsv_size, LMB_NOOVERWRITE);
	}

	if (IS_ENABLED(CONFIG_SPL_SEPARATE_BSS)) {
		/* Reserve the bss region */
		rsv_start = (phys_addr_t)(uintptr_t)__bss_start;
		rsv_size = (phys_addr_t)(uintptr_t)__bss_end -
			(phys_addr_t)(uintptr_t)__bss_start;
		lmb_reserve(rsv_start, rsv_size, LMB_NOOVERWRITE);
	}
}

/**
 * lmb_add_memory() - Add memory range for LMB allocations
 *
 * Add the entire available memory range to the pool of memory that
 * can be used by the LMB module for allocations.
 *
 * This can be overridden for specific boards/architectures.
 *
 * Return: None
 *
 */
__weak void lmb_add_memory(void)
{
	int i;
	phys_size_t size;
	phys_addr_t rgn_top;
	u64 ram_top = gd->ram_top;
	struct bd_info *bd = gd->bd;

	/* Assume a 4GB ram_top if not defined */
	if (!ram_top)
		ram_top = 0x100000000ULL;

	for (i = 0; i < CONFIG_NR_DRAM_BANKS; i++) {
		size = bd->bi_dram[i].size;
		if (size) {
			if (bd->bi_dram[i].start > ram_top)
				continue;

			rgn_top = bd->bi_dram[i].start +
				bd->bi_dram[i].size;

			if (rgn_top > ram_top)
				size -= rgn_top - ram_top;

			lmb_add(bd->bi_dram[i].start, size, LMB_NONE);
		}
	}
}

static bool lmb_region_flags_match(struct lmb_region *rgn, enum lmb_flags flags)
{
	return rgn->flags == flags;
}

static long lmb_resize_regions(struct list_head *lmb_rgn_lst,
			       struct lmb_rgn_node *rgn_first, phys_addr_t base,
			       phys_size_t size)
{
	phys_size_t rgnsize;
	phys_addr_t rgnbase, rgnend;
	phys_addr_t mergebase, mergeend;
	struct lmb_rgn_node *rgn_node, *rgn_end, *rgn_del;

	/*
	 * First thing to do is to identify how many regions
	 * the requested region overlaps.
	 * If the flags match, combine all these overlapping
	 * regions into a single region, and remove the merged
	 * regions.
	 */
	rgn_node = rgn_first;
	list_for_each_entry_from(rgn_node, lmb_rgn_lst, link) {
		rgnbase = rgn_node->rgn.base;
		rgnsize = rgn_node->rgn.size;

		if (lmb_addrs_overlap(base, size, rgnbase,
				      rgnsize)) {
			if (!lmb_region_flags_match(&rgn_node->rgn, LMB_NONE))
				return -1;
			rgn_end = rgn_node;
		}
	}

	/* The merged region's base and size */
	rgnbase = rgn_first->rgn.base;
	mergebase = min(base, rgnbase);
	rgnend = rgn_end->rgn.base + rgn_end->rgn.size;
	mergeend = max(rgnend, (base + size));

	rgn_first->rgn.base = mergebase;
	rgn_first->rgn.size = mergeend - mergebase;

	/* Now remove the merged regions */
	rgn_del = list_next_entry(rgn_first, link);
	list_for_each_entry_safe_from(rgn_del, rgn_node, lmb_rgn_lst, link) {
		rgnbase = rgn_del->rgn.base;
		rgnsize = rgn_del->rgn.size;

		if (lmb_addrs_overlap(base, size, rgnbase,
				      rgnsize)) {
			list_del(&rgn_del->link);
			free(rgn_del);
		}
	}

	return 0;
}

/**
 * lmb_add_region_flags() - Add an lmb region to the given list
 * @lmb_rgn_lst: LMB list to which region is to be added(free/used)
 * @base: Start address of the region
 * @size: Size of the region to be added
 * @flags: Attributes of the LMB region
 *
 * Add a region of memory to the list. If the region does not exist, add
 * it to the list. Depending on the attributes of the region to be added,
 * the function might resize an already existing region or coalesce two
 * adjacent regions.
 *
 *
 * Returns: 0 if the region addition successful, -1 on failure
 */
/* This routine called with relocation disabled. */
static long lmb_add_region_flags(struct list_head *lmb_rgn_lst,
				 phys_addr_t base, phys_size_t size,
				 enum lmb_flags flags)
{
	long ret;
	unsigned long coalesced = 0;
	struct lmb_rgn_node *new_rgn, *rgn_node;

	if (list_empty(lmb_rgn_lst)) {
		new_rgn = calloc(1, sizeof(*new_rgn));
		if (!new_rgn)
			return -1;

		new_rgn->rgn.base = base;
		new_rgn->rgn.size = size;
		new_rgn->rgn.flags = flags;
		list_add_tail(&new_rgn->link, lmb_rgn_lst);

		return 0;
	}

	/* First try and coalesce this LMB with another. */
	list_for_each_entry(rgn_node, lmb_rgn_lst, link) {
		struct lmb_region *rgn = &rgn_node->rgn;
		phys_addr_t rgnbase = rgn->base;
		phys_size_t rgnsize = rgn->size;
		phys_size_t rgnflags = rgn->flags;
		phys_addr_t end = base + size - 1;
		phys_addr_t rgnend = rgnbase + rgnsize - 1;

		if (rgnbase <= base && end <= rgnend) {
			if (flags == rgnflags)
				/* Already have this region, so we're done */
				return 0;
			else
				return -1; /* regions with new flags */
		}

		ret = lmb_addrs_adjacent(base, size, rgnbase, rgnsize);
		if (ret > 0) {
			if (flags != rgnflags)
				break;
			rgn->base -= size;
			rgn->size += size;
			coalesced++;
			break;
		} else if (ret < 0) {
			if (flags != rgnflags)
				break;
			rgn->size += size;
			coalesced++;
			break;
		} else if (lmb_addrs_overlap(base, size, rgnbase, rgnsize)) {
			if (flags == LMB_NONE) {
				ret = lmb_resize_regions(lmb_rgn_lst, rgn_node,
							 base, size);
				if (ret < 0)
					return -1;

				coalesced++;
				break;
			} else {
				return -1;
			}
		}
	}

	if (coalesced) {
		lmb_merge_adjacents(lmb_rgn_lst);

		return coalesced;
	}

	new_rgn = calloc(1, sizeof(*new_rgn));
	if (!new_rgn)
		return -1;

	new_rgn->rgn.base = base;
	new_rgn->rgn.size = size;
	new_rgn->rgn.flags = flags;
	list_add_tail(&new_rgn->link, lmb_rgn_lst);

	/*
	 * Sort the list now. This will take care of coalescing
	 * adjacent nodes, if needed.
	 */
	lmb_list_sort(lmb_rgn_lst);

	return 0;
}

/* This routine may be called with relocation disabled. */
long lmb_add(phys_addr_t base, phys_size_t size, uint flags)
{
	long ret;

	ret = lmb_add_region_flags(&lmb_free_mem, base, size, flags);
	if (ret)
		return ret;

	if (CONFIG_IS_ENABLED(MEM_MAP_UPDATE_NOTIFY))
		lmb_map_update_notify(base, size, MAP_OP_ADD);

	return 0;
}

static long __lmb_free(phys_addr_t base, phys_size_t size)
{
	struct lmb_region *rgn;
	struct lmb_rgn_node *used_node;
	phys_addr_t rgnbegin, rgnend;
	phys_addr_t end = base + size - 1;
	bool found;

	found = false;
	rgnbegin = rgnend = 0; /* supress gcc warnings */

	/* Find the region where (base, size) belongs to */
	list_for_each_entry(used_node, &lmb_used_mem, link) {
		rgn = &used_node->rgn;

		rgnbegin = rgn->base;
		rgnend = rgnbegin + rgn->size - 1;

		if ((rgnbegin <= base) && (end <= rgnend)) {
			found = true;
			break;
		}
	}

	/* Didn't find the region */
	if (!found)
		return -1;

	/* Check to see if we are removing entire region */
	if ((rgnbegin == base) && (rgnend == end)) {
		list_del(&used_node->link);
		free(used_node);
		return 0;
	}

	/* Check to see if region is matching at the front */
	if (rgnbegin == base) {
		rgn->base = end + 1;
		rgn->size -= size;
		return 0;
	}

	/* Check to see if the region is matching at the end */
	if (rgnend == end) {
		rgn->size -= size;
		return 0;
	}

	/*
	 * We need to split the entry -  adjust the current one to the
	 * beginging of the hole and add the region after hole.
	 */
	rgn->size = base - rgn->base;
	return lmb_add_region_flags(&lmb_used_mem, end + 1, rgnend - end,
				    rgn->flags);
}

long lmb_free(phys_addr_t base, phys_size_t size, uint flags)
{
	long ret;

	ret = __lmb_free(base, size);
	if (ret < 0)
		return ret;

	if (CONFIG_IS_ENABLED(MEM_MAP_UPDATE_NOTIFY) && lmb_notify(flags))
		lmb_map_update_notify(base, size, MAP_OP_FREE);

	return 0;
}

long lmb_reserve(phys_addr_t base, phys_size_t size, uint flags)
{
	long ret = 0;

	ret = lmb_add_region_flags(&lmb_used_mem, base, size, flags);
	if (ret < 0)
		return -1;

	if (CONFIG_IS_ENABLED(MEM_MAP_UPDATE_NOTIFY) && lmb_notify(flags))
		lmb_map_update_notify(base, size, MAP_OP_RESERVE);

	return ret;
}

static struct lmb_region *lmb_overlaps_region(struct list_head *lmb_rgn_lst,
					      phys_addr_t base,
					      phys_size_t size)
{
	unsigned long i, count;
	struct lmb_region *rgn;
	struct lmb_rgn_node *rgn_node;

	i = 0;
	count = list_count_nodes(lmb_rgn_lst);
	list_for_each_entry(rgn_node, lmb_rgn_lst, link) {
		rgn = &rgn_node->rgn;
		i++;

		phys_addr_t rgnbase = rgn->base;
		phys_size_t rgnsize = rgn->size;
		if (lmb_addrs_overlap(base, size, rgnbase, rgnsize))
			break;

	}

	return (i < count) ? rgn : NULL;
}

static phys_addr_t lmb_align_down(phys_addr_t addr, phys_size_t size)
{
	return addr & ~(size - 1);
}

static phys_addr_t __lmb_alloc_base(phys_size_t size, ulong align,
				    phys_addr_t max_addr, enum lmb_flags flags)
{
	phys_addr_t base = 0;
	phys_addr_t res_base;
	struct lmb_region *rgn;
	struct lmb_rgn_node *free_node;

	/*
	 * The memory regions are arranged in ascending order. Start
	 * traversing the list in reverse order to find consider higher
	 * address for allocation.
	 */
	list_for_each_entry_reverse(free_node, &lmb_free_mem, link) {
		phys_addr_t lmbbase = free_node->rgn.base;
		phys_size_t lmbsize = free_node->rgn.base;

		if (lmbsize < size)
			continue;
		if (max_addr == LMB_ALLOC_ANYWHERE)
			base = lmb_align_down(lmbbase + lmbsize - size, align);
		else if (lmbbase < max_addr) {
			base = lmbbase + lmbsize;
			if (base < lmbbase)
				base = -1;
			base = min(base, max_addr);
			base = lmb_align_down(base - size, align);
		} else
			continue;

		while (base && lmbbase <= base) {
			rgn = lmb_overlaps_region(&lmb_used_mem, base, size);
			if (!rgn) {
				/* This area isn't reserved, take it */
				if (lmb_add_region_flags(&lmb_used_mem, base,
							 size, flags) < 0)
					return 0;

				if (CONFIG_IS_ENABLED(MEM_MAP_UPDATE_NOTIFY) &&
				    lmb_notify(flags))
					lmb_map_update_notify(base, size,
							      MAP_OP_RESERVE);
				return base;
			}

			res_base = rgn->base;
			if (res_base < size)
				break;
			base = lmb_align_down(res_base - size, align);
		}
	}
	return 0;
}

phys_addr_t lmb_alloc(phys_size_t size, ulong align, uint flags)
{
	return lmb_alloc_base(size, align, LMB_ALLOC_ANYWHERE, flags);
}

phys_addr_t lmb_alloc_base(phys_size_t size, ulong align, phys_addr_t max_addr,
			   uint flags)
{
	phys_addr_t alloc;

	alloc = __lmb_alloc_base(size, align, max_addr, flags);

	if (alloc == 0)
		printf("ERROR: Failed to allocate 0x%lx bytes below 0x%lx.\n",
		       (ulong)size, (ulong)max_addr);

	return alloc;
}

static phys_addr_t __lmb_alloc_addr(phys_addr_t base, phys_size_t size,
				    enum lmb_flags flags)
{
	struct lmb_region *rgn;

	/* Check if the requested address is in one of the memory regions */
	rgn = lmb_overlaps_region(&lmb_free_mem, base, size);
	if (rgn) {
		/*
		 * Check if the requested end address is in the same memory
		 * region we found.
		 */
		if (lmb_addrs_overlap(rgn->base, rgn->size,
				      base + size - 1, 1)) {
			/* ok, reserve the memory */
			if (lmb_reserve(base, size, flags) >= 0)
				return base;
		}
	}

	return 0;
}

/*
 * Try to allocate a specific address range: must be in defined memory but not
 * reserved
 */
phys_addr_t lmb_alloc_addr(phys_addr_t base, phys_size_t size, uint flags)
{
	return __lmb_alloc_addr(base, size, flags);
}

/* Return number of bytes from a given address that are free */
phys_size_t lmb_get_free_size(phys_addr_t addr)
{
	struct lmb_region *rgn;
	struct lmb_rgn_node *used_node;
	struct lmb_rgn_node *free_node;

	/* check if the requested address is in the memory regions */
	rgn = lmb_overlaps_region(&lmb_free_mem, addr, 1);
	if (rgn) {
		list_for_each_entry(used_node, &lmb_used_mem, link) {
			rgn = &used_node->rgn;

			if (addr < rgn->base) {
				/* first reserved range > requested address */
				return rgn->base - addr;
			}
			if (rgn->base + rgn->size > addr) {
				/* requested addr is in this reserved range */
				return 0;
			}
		}
		/* if we come here: no reserved ranges above requested addr */
		free_node = list_last_entry(&lmb_free_mem, struct lmb_rgn_node,
					   link);
		return free_node->rgn.base + free_node->rgn.size - addr;
	}
	return 0;
}

int lmb_is_reserved_flags(phys_addr_t addr, int flags)
{
	struct lmb_rgn_node *rgn_node;

	list_for_each_entry(rgn_node, &lmb_used_mem, link) {
		struct lmb_region *rgn = &rgn_node->rgn;
		phys_addr_t upper = rgn->base + rgn->size - 1;

		if ((addr >= rgn->base) && (addr <= upper))
			return (rgn->flags & flags) == flags;
	}
	return 0;
}

__weak void board_lmb_reserve(void)
{
	/* please define platform specific board_lmb_reserve() */
}

__weak void arch_lmb_reserve(void)
{
	phys_addr_t rsv_start;

	rsv_start = gd->start_addr_sp - CONFIG_STACK_SIZE;

	arch_lmb_reserve_generic(rsv_start, gd->ram_top, 16384);
}

/**
 * lmb_mem_regions_init() - Initialise the LMB memory
 *
 * Initialise the LMB subsystem related data structures. There are two
 * alloced lists that are initialised, one for the free memory, and one
 * for the used memory.
 *
 * Initialise the two lists as part of board init.
 *
 * Return: 0 if OK, -ve on failure.
 */
int lmb_mem_regions_init(void)
{
	lmb_add_memory();

	/* Reserve the U-Boot image region once U-Boot has relocated */
	if (spl_phase() == PHASE_SPL)
		lmb_reserve_common_spl();
	else if (spl_phase() == PHASE_BOARD_R)
		lmb_reserve_common((void *)gd->fdt_blob);

	return 0;
}

/**
 * initr_lmb() - Initialise the LMB lists
 *
 * Initialise the LMB lists needed for keeping the memory map. There
 * are two lists, in form of alloced list data structure. One for the
 * available memory, and one for the used memory.
 *
 * Return: 0 on success, -ve on error
 */
int initr_lmb(void)
{
	int ret;

	ret = lmb_mem_regions_init();
	if (ret)
		printf("Unable to initialise the LMB data structures\n");

	return ret;
}
