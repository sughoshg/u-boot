/* SPDX-License-Identifier: GPL-2.0+ */
/*
 * Copyright (c) 2022, Linaro Limited
 */

#if !defined _FWU_H_
#define _FWU_H_

#include <blk.h>
#include <efi.h>

#include <linux/types.h>

struct fwu_mdata;
struct udevice;

/**
 * @get_image_alt_num: get the alt number to be used for the image
 * @mdata_check: check the validity of the FWU metadata partitions
 * @get_mdata() - Get a FWU metadata copy
 * @update_mdata() - Update the FWU metadata copy
 */
struct fwu_mdata_ops {
	int (*get_image_alt_num)(struct udevice *dev, efi_guid_t image_type_id,
				 u32 update_bank, int *alt_num);

	int (*mdata_check)(struct udevice *dev);

	int (*get_mdata)(struct udevice *dev, struct fwu_mdata **mdata);

	int (*update_mdata)(struct udevice *dev, struct fwu_mdata *mdata);
};

#define FWU_MDATA_VERSION	0x1
#define FWU_IMAGE_ACCEPTED	0x1

#define FWU_MDATA_GUID \
	EFI_GUID(0x8a7a84a0, 0x8387, 0x40f6, 0xab, 0x41, \
		 0xa8, 0xb9, 0xa5, 0xa6, 0x0d, 0x23)

#define FWU_OS_REQUEST_FW_REVERT_GUID \
	EFI_GUID(0xacd58b4b, 0xc0e8, 0x475f, 0x99, 0xb5, \
		 0x6b, 0x3f, 0x7e, 0x07, 0xaa, 0xf0)

#define FWU_OS_REQUEST_FW_ACCEPT_GUID \
	EFI_GUID(0x0c996046, 0xbcc0, 0x4d04, 0x85, 0xec, \
		 0xe1, 0xfc, 0xed, 0xf1, 0xc6, 0xf8)

u8 fwu_update_checks_pass(void);
int fwu_boottime_checks(void);
int fwu_trial_state_ctr_start(void);

int fwu_get_mdata(struct fwu_mdata **mdata);
int fwu_update_mdata(struct fwu_mdata *mdata);
int fwu_get_active_index(u32 *active_idx);
int fwu_update_active_index(u32 active_idx);
int fwu_get_image_alt_num(efi_guid_t image_type_id, u32 update_bank,
			  int *alt_num);
int fwu_get_mdata_device(struct udevice *dev, struct udevice **mdata_dev);
int fwu_verify_mdata(struct fwu_mdata *mdata, bool pri_part);
int fwu_mdata_check(void);
int fwu_revert_boot_index(void);
int fwu_accept_image(efi_guid_t *img_type_id, u32 bank);
int fwu_clear_accept_image(efi_guid_t *img_type_id, u32 bank);

int fwu_plat_get_update_index(u32 *update_idx);
int fwu_plat_get_alt_num(struct udevice *dev, void *identifier);
void fwu_plat_get_bootidx(void *boot_idx);

#endif /* _FWU_H_ */
