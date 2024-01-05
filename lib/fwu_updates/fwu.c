// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2022, Linaro Limited
 */

#include <dm.h>
#include <efi.h>
#include <efi_loader.h>
#include <efi_variable.h>
#include <event.h>
#include <fwu.h>
#include <fwu_mdata.h>
#include <malloc.h>

#include <linux/errno.h>
#include <linux/types.h>

#include <u-boot/crc.h>

static struct fwu_mdata *g_mdata;
static struct udevice *g_dev;
static u8 in_trial;
static u8 boottime_check;

enum {
	IMAGE_ACCEPT_SET = 1,
	IMAGE_ACCEPT_CLEAR,
};

enum {
	PRIMARY_PART = 1,
	SECONDARY_PART,
	BOTH_PARTS,
};

static int trial_counter_update(u16 *trial_state_ctr)
{
	bool delete;
	u32 var_attr;
	efi_status_t status;
	efi_uintn_t var_size;

	delete = !trial_state_ctr ? true : false;
	var_size = !trial_state_ctr ? 0 : (efi_uintn_t)sizeof(*trial_state_ctr);
	var_attr = !trial_state_ctr ? 0 : EFI_VARIABLE_NON_VOLATILE |
		EFI_VARIABLE_BOOTSERVICE_ACCESS;
	status = efi_set_variable_int(u"TrialStateCtr",
				      &efi_global_variable_guid,
				      var_attr,
				      var_size, trial_state_ctr, false);

	if ((delete && (status != EFI_NOT_FOUND &&
			status != EFI_SUCCESS)) ||
	    (!delete && status != EFI_SUCCESS))
		return -1;

	return 0;
}

static int trial_counter_read(u16 *trial_state_ctr)
{
	efi_status_t status;
	efi_uintn_t var_size;

	var_size = (efi_uintn_t)sizeof(trial_state_ctr);
	status = efi_get_variable_int(u"TrialStateCtr",
				      &efi_global_variable_guid,
				      NULL,
				      &var_size, trial_state_ctr,
				      NULL);
	if (status != EFI_SUCCESS) {
		log_err("Unable to read TrialStateCtr variable\n");
		return -1;
	}

	return 0;
}

static int fwu_trial_count_update(void)
{
	int ret;
	u16 trial_state_ctr;

	ret = trial_counter_read(&trial_state_ctr);
	if (ret) {
		log_debug("Unable to read trial_state_ctr\n");
		goto out;
	}

	++trial_state_ctr;
	if (trial_state_ctr > CONFIG_FWU_TRIAL_STATE_CNT) {
		log_info("Trial State count exceeded. Revert back to previous_active_index\n");
		ret = fwu_revert_boot_index();
		if (ret)
			log_err("Unable to revert active_index\n");
		ret = 1;
	} else {
		log_info("Trial State count: attempt %d out of %d\n",
			 trial_state_ctr, CONFIG_FWU_TRIAL_STATE_CNT);
		ret = trial_counter_update(&trial_state_ctr);
		if (ret)
			log_err("Unable to increment TrialStateCtr variable\n");
	}

out:
	return ret;
}

static int in_trial_state(struct fwu_mdata *mdata)
{
	u32 active_bank = mdata->active_index;

	return mdata->bank_state[active_bank] == FWU_BANK_VALID ? 1 : 0;
}

static int fwu_get_image_type_id(u8 *image_index, efi_guid_t *image_type_id)
{
	u8 index;
	int i;
	struct efi_fw_image *image;

	index = *image_index;
	image = update_info.images;
	for (i = 0; i < update_info.num_images; i++) {
		if (index == image[i].image_index) {
			guidcpy(image_type_id, &image[i].image_type_id);
			return 0;
		}
	}

	return -ENOENT;
}

/**
 * fwu_sync_mdata() - Update given meta-data partition(s) with the copy provided
 * @mdata: FWU metadata structure
 * @part: Bitmask of FWU metadata partitions to be written to
 *
 * Return: 0 if OK, -ve on error
 */
static int fwu_sync_mdata(struct fwu_mdata *mdata, int part)
{
	int err;
	uint32_t mdata_size;
	void *buf = &mdata->version;

	if (part == BOTH_PARTS) {
		err = fwu_sync_mdata(mdata, SECONDARY_PART);
		if (err)
			return err;
		part = PRIMARY_PART;
	}

	/*
	 * Calculate the crc32 for the updated FWU metadata
	 * and put the updated value in the FWU metadata crc32
	 * field
	 */
	mdata_size = mdata->metadata_size;
	mdata->crc32 = crc32(0, buf, mdata_size - sizeof(u32));

	err = fwu_write_mdata(g_dev, mdata, part == PRIMARY_PART, mdata_size);
	if (err) {
		log_err("Unable to write %s mdata\n",
			part == PRIMARY_PART ?  "primary" : "secondary");
		return err;
	}

	/* update the cached copy of meta-data */
	memcpy(g_mdata, mdata, mdata_size);

	return 0;
}

static inline int mdata_crc_check(struct fwu_mdata *mdata)
{
	void *buf = &mdata->version;
	u32 calc_crc32;

	if (!mdata->metadata_size)
		return -EINVAL;

	calc_crc32 = crc32(0, buf, mdata->metadata_size - sizeof(u32));
	return calc_crc32 == mdata->crc32 ? 0 : -EINVAL;
}

static int fwu_copies_allocate(void)
{
	int err;
	uint32_t mdata_size;

	err = fwu_get_mdata_size(&mdata_size);
	if (err)
		return err;

	/*
	 * Now allocate the total memory that would be needed for both
	 * the copies.
	 */
	g_mdata = malloc(mdata_size * 2);
	if (!g_mdata) {
		log_err("Unable to allocate space for FWU metadata\n");
		return -ENOMEM;
	}

	memset(g_mdata, 0, mdata_size * 2);

	return 0;
}

/**
 * fwu_get_mdata_size() - Get the FWU metadata size
 *
 * Get the size of the FWU metadata from the structure. This is later used
 * to allocate memory for the structure.
 *
 * Return: 0 if OK, -ve on error
 */
int fwu_get_mdata_size(uint32_t *mdata_size)
{
	int err = 0;
	struct fwu_mdata mdata = { 0 };

	if (g_mdata && !mdata_crc_check(g_mdata)) {
		*mdata_size = g_mdata->metadata_size;
		return 0;
	}

	err = fwu_read_mdata(g_dev, &mdata, 1, sizeof(struct fwu_mdata));
	if (err) {
		log_err("FWU metadata read failed\n");
		return err;
	}

	if (mdata.version != 0x2) {
		log_err("FWU metadata version %u. Expected value of 2\n",
			mdata.version);
		return -EINVAL;
	}

	*mdata_size = mdata.metadata_size;
	if (!*mdata_size)
		return -EINVAL;

	return 0;
}

/**
 * fwu_get_dev() - Return the FWU metadata device
 *
 * Return the pointer to the FWU metadata device.
 *
 * Return: Pointer to the FWU metadata dev
 */
__maybe_unused struct udevice *fwu_get_dev(void)
{
	return g_dev;
}

/**
 * fwu_get_banks_images() - Get the number of banks and images from the metadata
 * @nbanks: Number of banks
 * @nimages: Number of images per bank
 *
 * Get the values of number of banks and number of images per bank from the
 * metadata.
 *
 * Return: 0 if OK, -ve on error
 */
__maybe_unused int fwu_get_banks_images(u8 *nbanks, u16 *nimages)
{
	int ret;

	if (mdata_crc_check(g_mdata)) {
		ret = fwu_get_mdata(NULL);
		if (ret)
			return ret;
	}

	*nbanks = g_mdata->fw_desc[0].num_banks;
	*nimages = g_mdata->fw_desc[0].num_images;

	return 0;
}

/**
 * fwu_get_mdata() - Read, verify and return the FWU metadata
 * @mdata: Output FWU metadata read or NULL
 *
 * Read both the metadata copies from the storage media, verify their checksum,
 * and ascertain that both copies match. If one of the copies has gone bad,
 * restore it from the good copy.
 *
 * Return: 0 if OK, -ve on error
 */
int fwu_get_mdata(struct fwu_mdata *mdata)
{
	int err;
	uint32_t mdata_size;
	bool parts_ok[2] = { false };
	struct fwu_mdata *parts_mdata[2];

	err = fwu_get_mdata_size(&mdata_size);
	if (err)
		return err;

	parts_mdata[0] = g_mdata;
	parts_mdata[1] = (struct fwu_mdata *)((char *)g_mdata + mdata_size);

	/* if mdata already read and ready */
	if (!mdata_crc_check(parts_mdata[0]))
		goto ret_mdata;

	/* else read, verify and, if needed, fix mdata */
	for (int i = 0; i < 2; i++) {
		parts_ok[i] = false;
		err = fwu_read_mdata(g_dev, parts_mdata[i], !i, mdata_size);
		if (!err) {
			err = mdata_crc_check(parts_mdata[i]);
			if (!err)
				parts_ok[i] = true;
			else
				log_debug("mdata : %s crc32 failed\n",
					  i ? "secondary" : "primary");
		}
	}

	if (parts_ok[0] && parts_ok[1]) {
		/*
		 * Before returning, check that both the
		 * FWU metadata copies are the same.
		 */
		err = memcmp(parts_mdata[0], parts_mdata[1],
			     mdata_size);
		if (!err)
			goto ret_mdata;

		/*
		 * If not, populate the secondary partition from the
		 * primary partition copy.
		 */
		log_info("Both FWU metadata copies are valid but do not match.");
		log_info(" Restoring the secondary partition from the primary\n");
		parts_ok[1] = false;
	}

	for (int i = 0; i < 2; i++) {
		if (parts_ok[i])
			continue;

		memcpy(parts_mdata[i], parts_mdata[1 - i],
		       mdata_size);
		err = fwu_sync_mdata(parts_mdata[i], i ? SECONDARY_PART : PRIMARY_PART);
		if (err) {
			log_debug("mdata : %s write failed\n", i ? "secondary" : "primary");
			return err;
		}
	}

ret_mdata:
	if (!err && mdata)
		memcpy(mdata, parts_mdata[0], mdata_size);

	return err;
}

/**
 * fwu_get_active_index() - Get active_index from the FWU metadata
 * @active_idx: active_index value to be read
 *
 * Read the active_index field from the FWU metadata and place it in
 * the variable pointed to be the function argument.
 *
 * Return: 0 if OK, -ve on error
 *
 */
int fwu_get_active_index(uint *active_idx)
{
	int ret = 0;
	u8 num_banks;
	struct fwu_mdata *mdata = g_mdata;

	/*
	 * Found the FWU metadata partition, now read the active_index
	 * value
	 */
	*active_idx = mdata->active_index;
	num_banks = mdata->fw_desc[0].num_banks;
	if (*active_idx >= num_banks) {
		log_debug("Active index value read is incorrect\n");
		ret = -EINVAL;
	}

	return ret;
}

/**
 * fwu_set_active_index() - Set active_index in the FWU metadata
 * @active_idx: active_index value to be set
 *
 * Update the active_index field in the FWU metadata
 *
 * Return: 0 if OK, -ve on error
 *
 */
int fwu_set_active_index(uint active_idx)
{
	int ret;
	u8 num_banks;
	struct fwu_mdata *mdata = g_mdata;

	num_banks = mdata->fw_desc[0].num_banks;
	if (active_idx >= num_banks) {
		log_debug("Invalid active index value\n");
		return -EINVAL;
	}

	/*
	 * Update the active index and previous_active_index fields
	 * in the FWU metadata
	 */
	mdata->previous_active_index = mdata->active_index;
	mdata->active_index = active_idx;

	/*
	 * Now write this updated FWU metadata to both the
	 * FWU metadata partitions
	 */
	ret = fwu_sync_mdata(mdata, BOTH_PARTS);
	if (ret) {
		log_debug("Failed to update FWU metadata partitions\n");
		ret = -EIO;
	}

	return ret;
}

/**
 * fwu_get_image_index() - Get the Image Index to be used for capsule update
 * @image_index: The Image Index for the image
 *
 * The FWU multi bank update feature computes the value of image_index at
 * runtime, based on the bank to which the image needs to be written to.
 * Derive the image_index value for the image.
 *
 * Currently, the capsule update driver uses the DFU framework for
 * the updates. This function gets the DFU alt number which is to
 * be used as the Image Index
 *
 * Return: 0 if OK, -ve on error
 *
 */
int fwu_get_image_index(u8 *image_index)
{
	int ret, i;
	u8 alt_num;
	u16 num_images;
	uint update_bank;
	efi_guid_t *image_guid, image_type_id;
	struct fwu_mdata *mdata = g_mdata;
	struct fwu_image_entry *img_entry;
	struct fwu_image_bank_info *img_bank_info;

	ret = fwu_plat_get_update_index(&update_bank);
	if (ret) {
		log_debug("Failed to get the FWU update bank\n");
		goto out;
	}

	ret = fwu_get_image_type_id(image_index, &image_type_id);
	if (ret) {
		log_debug("Unable to get image_type_id for image_index %u\n",
			  *image_index);
		goto out;
	}

	ret = -EINVAL;
	/*
	 * The FWU metadata has been read. Now get the image_guid for the
	 * image with the update_bank.
	 */
	num_images = mdata->fw_desc[0].num_images;
	for (i = 0; i < num_images; i++) {
		if (!guidcmp(&image_type_id,
			     &mdata->fw_desc[0].img_entry[i].image_type_guid)) {
			img_entry = &mdata->fw_desc[0].img_entry[i];
			img_bank_info = &img_entry->img_bank_info[update_bank];
			image_guid = &img_bank_info->image_guid;
			ret = fwu_plat_get_alt_num(g_dev, image_guid, &alt_num);
			if (ret) {
				log_debug("alt_num not found for partition with GUID %pUs\n",
					  image_guid);
			} else {
				log_debug("alt_num %d for partition %pUs\n",
					  alt_num, image_guid);
				*image_index = alt_num + 1;
			}

			goto out;
		}
	}

	log_err("Partition with the image type %pUs not found\n",
		&image_type_id);

out:
	return ret;
}

/**
 * fwu_revert_boot_index() - Revert the active index in the FWU metadata
 *
 * Revert the active_index value in the FWU metadata, by swapping the values
 * of active_index and previous_active_index in both copies of the
 * FWU metadata.
 *
 * Return: 0 if OK, -ve on error
 *
 */
int fwu_revert_boot_index(void)
{
	int ret;
	u32 cur_active_index;
	struct fwu_mdata *mdata = g_mdata;

	/*
	 * Swap the active index and previous_active_index fields
	 * in the FWU metadata
	 */
	cur_active_index = mdata->active_index;
	mdata->active_index = mdata->previous_active_index;
	mdata->previous_active_index = cur_active_index;

	/*
	 * Now write this updated FWU metadata to both the
	 * FWU metadata partitions
	 */
	ret = fwu_sync_mdata(mdata, BOTH_PARTS);
	if (ret) {
		log_debug("Failed to update FWU metadata partitions\n");
		ret = -EIO;
	}

	return ret;
}

/**
 * fwu_clrset_image_accept() - Set or Clear the Acceptance bit for the image
 * @img_type_id: GUID of the image type for which the accepted bit is to be
 *               set or cleared
 * @bank: Bank of which the image's Accept bit is to be set or cleared
 * @action: Action which specifies whether image's Accept bit is to be set or
 *          cleared
 *
 * Set/Clear the accepted bit for the image specified by the img_guid parameter.
 * This indicates acceptance or rejection of image for subsequent boots by some
 * governing component like OS(or firmware).
 *
 * Return: 0 if OK, -ve on error
 *
 */
static int fwu_clrset_image_accept(efi_guid_t *img_type_id, u32 bank, u8 action)
{
	int ret, i;
	u16 num_images;
	struct fwu_mdata *mdata = g_mdata;
	struct fwu_image_entry *img_entry;
	struct fwu_image_bank_info *img_bank_info;

	img_entry = &mdata->fw_desc[0].img_entry[0];
	num_images = mdata->fw_desc[0].num_images;
	for (i = 0; i < num_images; i++) {
		if (!guidcmp(&img_entry[i].image_type_guid, img_type_id)) {
			img_bank_info = &img_entry[i].img_bank_info[bank];
			if (action == IMAGE_ACCEPT_SET)
				img_bank_info->accepted |= FWU_IMAGE_ACCEPTED;
			else
				img_bank_info->accepted = 0;

			ret = fwu_sync_mdata(mdata, BOTH_PARTS);
			goto out;
		}
	}

	/* Image not found */
	ret = -ENOENT;

out:
	return ret;
}

static int fwu_trial_state_ctr_start(void)
{
	int ret;
	u16 trial_state_ctr;

	printf("%s: starting the TrialStateCtr\n", __func__);
	trial_state_ctr = 0;
	ret = trial_counter_update(&trial_state_ctr);
	if (ret)
		log_err("Unable to initialise TrialStateCtr\n");

	return ret;
}

static int fwu_set_bank_state_trial(uint update_index)
{
	int ret;
	struct fwu_mdata *mdata = g_mdata;

	mdata->bank_state[update_index] = FWU_BANK_VALID;

	ret = fwu_sync_mdata(mdata, BOTH_PARTS);
	if (ret) {
		log_err("Unable to set bank_state for %d bank\n", update_index);
		return ret;
	}

	return 0;
}

/**
 * fwu_bank_state_update() - Check and update the bank_state of the metadata
 * @update_index: Bank for which the bank_state needs to be updated
 *
 * Check that all the images for the given bank have been accepted, and if
 * they are, set the status of the bank to Accepted in the bank_state field
 * of the metadata.
 *
 * Return: 0 if OK, -ve on error
 */
int fwu_bank_state_update(uint update_index)
{
	int ret = 0, i;
	u16 num_images;
	struct fwu_mdata *mdata = g_mdata;
	struct fwu_image_entry *img_entry;
	struct fwu_image_bank_info *img_bank_info;

	img_entry = &mdata->fw_desc[0].img_entry[0];
	num_images = mdata->fw_desc[0].num_images;
	for (i = 0; i < num_images; i++) {
		img_bank_info = &img_entry[i].img_bank_info[update_index];
		if (!(img_bank_info->accepted & FWU_IMAGE_ACCEPTED))
			return 0;
	}

	mdata->bank_state[update_index] = FWU_BANK_ACCEPTED;
	ret = fwu_sync_mdata(mdata, BOTH_PARTS);
	if (ret)
		log_err("Unable to set bank_state for bank %u\n", update_index);

	return ret;
}

/**
 * fwu_accept_image() - Set the Acceptance bit for the image
 * @img_type_id: GUID of the image type for which the accepted bit is to be
 *               cleared
 * @bank: Bank of which the image's Accept bit is to be set
 *
 * Set the accepted bit for the image specified by the img_guid parameter. This
 * indicates acceptance of image for subsequent boots by some governing component
 * like OS(or firmware).
 *
 * Return: 0 if OK, -ve on error
 *
 */
int fwu_accept_image(efi_guid_t *img_type_id, u32 bank)
{
	return fwu_clrset_image_accept(img_type_id, bank,
				       IMAGE_ACCEPT_SET);
}

/**
 * fwu_clear_accept_image() - Clear the Acceptance bit for the image
 * @img_type_id: GUID of the image type for which the accepted bit is to be
 *               cleared
 * @bank: Bank of which the image's Accept bit is to be cleared
 *
 * Clear the accepted bit for the image type specified by the img_type_id parameter.
 * This function is called after the image has been updated. The accepted bit is
 * cleared to be set subsequently after passing the image acceptance criteria, by
 * either the OS(or firmware)
 *
 * Return: 0 if OK, -ve on error
 *
 */
int fwu_clear_accept_image(efi_guid_t *img_type_id, u32 bank)
{
	return fwu_clrset_image_accept(img_type_id, bank,
				       IMAGE_ACCEPT_CLEAR);
}

/**
 * fwu_plat_get_update_index() - Get the value of the update bank
 * @update_idx: Bank number to which images are to be updated
 *
 * Get the value of the bank(partition) to which the update needs to be
 * made.
 *
 * Note: This is a weak function and platforms can override this with
 * their own implementation for selection of the update bank.
 *
 * Return: 0 if OK, -ve on error
 *
 */
__weak int fwu_plat_get_update_index(uint *update_idx)
{
	int ret;
	u32 active_idx;
	u8 num_banks;
	struct fwu_mdata *mdata = g_mdata;

	ret = fwu_get_active_index(&active_idx);
	if (ret < 0)
		return -1;

	num_banks = mdata->fw_desc[0].num_banks;
	*update_idx = (active_idx + 1) % num_banks;

	return ret;
}

/**
 * fwu_plat_get_bootidx() - Get the value of the boot index
 * @boot_idx: Boot index value
 *
 * Get the value of the bank(partition) from which the platform
 * has booted. This value is passed to U-Boot from the earlier
 * stage bootloader which loads and boots all the relevant
 * firmware images
 */
__weak void fwu_plat_get_bootidx(uint *boot_idx)
{
	int ret;

	ret = fwu_get_active_index(boot_idx);
	if (ret < 0)
		*boot_idx = 0; /* Dummy value */
}

/**
 * fwu_update_checks_pass() - Check if FWU update can be done
 *
 * Check if the FWU update can be executed. The updates are
 * allowed only when the platform is not in Trial State and
 * the boot time checks have passed
 *
 * Return: 1 if OK, 0 if checks do not pass
 *
 */
u8 fwu_update_checks_pass(void)
{
	return !in_trial && boottime_check;
}

/**
 * fwu_empty_capsule_checks_pass() - Check if empty capsule can be processed
 *
 * Check if the empty capsule can be processed to either accept or revert
 * an earlier executed update. The empty capsules need to be processed
 * only when the platform is in Trial State and the boot time checks have
 * passed
 *
 * Return: 1 if OK, 0 if not to be allowed
 *
 */
u8 fwu_empty_capsule_checks_pass(void)
{
	return in_trial && boottime_check;
}

/**
 * fwu_trial_state_start() - Put the platform in Trial State
 * @update_index: Bank number to which images have been updated
 *
 * Put the platform in Trial State by starting the counter to
 * identify the platform booting in the Trial State. The
 * counter is implemented as an EFI variable. Secondly, set
 * the bank_state in the metadata for the updated bank to Valid
 * state.
 *
 * Return: 0 if OK, -ve on error
 *
 */
int fwu_trial_state_start(uint update_index)
{
	int ret;

	ret = fwu_trial_state_ctr_start();
	if (ret)
		return ret;

	ret = fwu_set_bank_state_trial(update_index);
	if (ret)
		return ret;

	return 0;
}

static int fwu_boottime_checks(void)
{
	int ret;
	u8 num_banks;
	u32 boot_idx, active_idx;

	ret = uclass_first_device_err(UCLASS_FWU_MDATA, &g_dev);
	if (ret) {
		log_debug("Cannot find fwu device\n");
		return ret;
	}

	/* Don't have boot time checks on sandbox */
	if (IS_ENABLED(CONFIG_SANDBOX)) {
		boottime_check = 1;
		return 0;
	}

	ret = fwu_copies_allocate();
	if (ret) {
		log_err("Unable to allocate memory for the metadata copies\n");
		return ret;
	}

	ret = fwu_get_mdata(NULL);
	if (ret) {
		log_debug("Unable to read meta-data\n");
		return ret;
	}

	/*
	 * Get the Boot Index, i.e. the bank from
	 * which the platform has booted. This value
	 * gets passed from the ealier stage bootloader
	 * which booted u-boot, e.g. tf-a. If the
	 * boot index is not the same as the
	 * active_index read from the FWU metadata,
	 * update the active_index.
	 */
	fwu_plat_get_bootidx(&boot_idx);
	num_banks = g_mdata->fw_desc[0].num_banks;
	if (boot_idx >= num_banks) {
		log_err("Received incorrect value of boot_index\n");
		return 0;
	}

	ret = fwu_get_active_index(&active_idx);
	if (ret) {
		log_err("Unable to read active_index\n");
		return 0;
	}

	if (boot_idx != active_idx) {
		log_info("Boot idx %u is not matching active idx %u, changing active_idx\n",
			 boot_idx, active_idx);
		ret = fwu_set_active_index(boot_idx);
		if (!ret)
			boottime_check = 1;
	}

	if (efi_init_obj_list() != EFI_SUCCESS)
		return 0;

	in_trial = in_trial_state(g_mdata);
	if (!in_trial || (ret = fwu_trial_count_update()) > 0)
		ret = trial_counter_update(NULL);

	if (!ret)
		boottime_check = 1;

	return 0;
}
EVENT_SPY_SIMPLE(EVT_MAIN_LOOP, fwu_boottime_checks);
