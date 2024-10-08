// SPDX-License-Identifier: GPL-2.0+
/*
 *  Allocate and Free LMB memory
 *
 *  Copyright (c) 2024 Linaro Limited
 */

#include <command.h>
#include <lmb.h>
#include <vsprintf.h>

#include <linux/types.h>

static int do_lmb_mem_free(struct cmd_tbl *cmdtp, int flag, int argc,
			   char * const argv[])
{
	long ret;
	phys_addr_t addr = 0;
	phys_size_t size = 0;

	if (argc != 3)
		return CMD_RET_USAGE;

	argc--; argv++;

	size = simple_strtoul(argv[0], NULL, 16);
	if (!size) {
		printf("Enter valid size for free in Hex\n");
		return CMD_RET_USAGE;
	}

	addr = simple_strtoul(argv[1], NULL, 16);
	if (!addr) {
		printf("Enter a valid address in Hex\n");
		return CMD_RET_USAGE;
	}

	ret = lmb_free(addr, size);
	if (ret) {
		printf("Unable to free memory\n");
		return CMD_RET_FAILURE;
	}

	return CMD_RET_SUCCESS;
}

static int do_lmb_mem_alloc(struct cmd_tbl *cmdtp, int flag, int argc,
			    char * const argv[])
{
	phys_addr_t addr = 0;
	phys_size_t size = 0;
	bool max = false;

	if (argc < 2)
		return CMD_RET_USAGE;

	argc--; argv++;

	if (!strcmp("max", argv[0])) {
		if (argc != 3)
			return CMD_RET_USAGE;

		max = true;
		argv++;
		argc--;
	}

	size = simple_strtoul(argv[0], NULL, 16);
	if (!size) {
		printf("Enter valid size for allocation in Hex\n");
		return CMD_RET_USAGE;
	}

	if (max || argc == 2) {
		addr = simple_strtoul(argv[1], NULL, 16);
		if (!addr) {
			printf("Enter a valid address in Hex\n");
			return CMD_RET_USAGE;
		}
	}

	if (max)
		addr = lmb_alloc_base(size, 0x1000, addr);
	else if (addr)
		addr = lmb_alloc_addr(addr, size);
	else
		addr = lmb_alloc(size, 0x1000);

	if (!addr) {
		printf("LMB allocation failed\n");
		return CMD_RET_FAILURE;
	} else {
		printf("Address returned %#llx\n", addr);
	}

	return CMD_RET_SUCCESS;
}

static struct cmd_tbl cmd_lmb_mem_sub[] = {
	U_BOOT_CMD_MKENT(alloc, 3, 0, do_lmb_mem_alloc,
		"", ""),
	U_BOOT_CMD_MKENT(free, 2, 0, do_lmb_mem_free,
		"", ""),
};

static int do_lmb_mem(struct cmd_tbl *cmdtp, int flag, int argc,
		      char *const argv[])
{
	struct cmd_tbl *cp;

	if (argc < 3)
		return CMD_RET_USAGE;

	argc--; argv++;

	cp = find_cmd_tbl(argv[0], cmd_lmb_mem_sub,
			  ARRAY_SIZE(cmd_lmb_mem_sub));
	if (!cp)
		return CMD_RET_USAGE;

	return cp->cmd(cmdtp, flag, argc, argv);
}


U_BOOT_LONGHELP(lmb_mem,
	"Functions to allocate and free LMB memory\n"
	"\n"
	"lmb_mem alloc <size> [addr]\n"
	"lmb_mem alloc max <size> <max-addr>\n"
	"lmb_mem free <size> <addr>\n"
	"\n"
);

U_BOOT_CMD(
	lmb_mem, CONFIG_SYS_MAXARGS, 0, do_lmb_mem,
	"Allocate and free LMB memory",
	lmb_mem_help_text
);
