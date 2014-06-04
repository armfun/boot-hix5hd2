/*
 * Warp!! boot driver  Rev. 4.0.3
 *
 *  Copyright (C) 2008-2013  Lineo Solutions, Inc.
 *
 */

#include <common.h>
#include <command.h>
#include <version.h>
#include <warp.h>
#include <flash_part.h>

#ifndef U_BOOT_VERSION_CODE
#define U_BOOT_VERSION_CODE     0
#endif

#ifndef U_BOOT_VER
#define U_BOOT_VER(a,b,c)       (((a) << 16) + ((b) << 8) + (c))
#endif

#if U_BOOT_VERSION_CODE < U_BOOT_VER(2010,9,0)
#define CMD_CONST
#else
#define CMD_CONST       const
#endif

#ifdef CONFIG_WARP

#define CONFIG_WARP_NAND
#define CONFIG_WARP_DRV_DEV WARP_DEV_NAND
#define CONFIG_WARP_SAVENO      0

static unsigned int warp_drv_area;
static unsigned int warp_drv_addr;
static unsigned int warp_drv_size;
static unsigned int warp_flag_area;
static unsigned int warp_flag_size;
static unsigned int warp_data_area;
static unsigned int warp_data_size;

#define WARP_HIBDRV_SIZE        0x00300000
#define WARP_TAG_SIZE           128

#define WARP_MODE_OFFSET        0x100000
#define NORMAL_MODE             0x303631
#define WARP_MODE               0x313631

struct warp_savearea warp_savearea[2] = {
/*
        CONFIG_WARP_SAVEAREA
*/
	{0}
};

int warp_saveno = CONFIG_WARP_SAVENO;

void *warp_bfaddr;

static int check_boot_ok = 0;

#ifdef CONFIG_WARP_NOR

#if (CONFIG_WARP_DRV_DEV & WARP_DEV_MASK) == WARP_DEV_NOR

static int warp_nor_drvload(void)
{
	int size;

	if (*(int *)(CONFIG_WARP_DRV_BASE + warp_drv_area + WARP_HEADER_ID)
	    != WARP_ID_DRIVER)
		return 1;
	size = *(int *)(CONFIG_WARP_DRV_BASE + warp_drv_area +
			WARP_HEADER_COPY_SIZE);
	memcpy((void *)warp_drv_addr,
	       (void *)(CONFIG_WARP_DRV_BASE + warp_drv_area), size);
	flush_cache(warp_drv_addr, size);
	return 0;
}

#endif

static int warp_nor_bfload(int saveno)
{
	void *bfaddr;

	bfaddr = (void *)CONFIG_WARP_BF_BASE + warp_savearea[saveno].bootflag_area;
	memcpy(warp_bfaddr, bfaddr, WARP_BF_LEN);

	return 0;
}

static int warp_nor_bferase(int saveno)
{
	unsigned long off, end;
	char cmd[256];

	off = CONFIG_WARP_BF_BASE + warp_savearea[saveno].bootflag_area;
	end = off + warp_savearea[saveno].bootflag_size - 1;
	printf("Warp!! bootflag clear NOR: 0x%08lx-0x%08lx\n", off, end);

	sprintf(cmd, "protect off 0x%08lx 0x%08lx", off, end);
	run_command(cmd, 0);
	sprintf(cmd, "erase 0x%08lx 0x%08lx", off, end);
	run_command(cmd, 0);
	return 0;
}

#endif

#ifdef CONFIG_WARP_NAND

#include <nand.h>

static unsigned long warp_nand_skipbad(nand_info_t * nand, unsigned long off,
				       unsigned long size)
{
	unsigned long end = off + size;

	while (off < end) {
		if (!nand_block_isbad(nand, off))
			return off;
		off += nand->erasesize;
	}

	return (unsigned long)-1;
}

#if (CONFIG_WARP_DRV_DEV & WARP_DEV_MASK) == WARP_DEV_NAND

static int warp_nand_drvload(void)
{
	int ret;
	unsigned long size, off;
	nand_info_t *nand = &nand_info[0];

	off = warp_nand_skipbad(nand, warp_drv_area, warp_drv_size);
	if (off == (unsigned long)-1)
		return 1;

	size = WARP_DRV_PRELOAD;
	if ((ret = nand_read(nand, off, &size, (void *)warp_drv_addr)) == 0) {
		if (*(int *)(warp_drv_addr + WARP_HEADER_ID) != WARP_ID_DRIVER)
			return 1;
		size = *(int *)(warp_drv_addr + WARP_HEADER_COPY_SIZE) -
		    WARP_DRV_PRELOAD;
		if (size <= 0 ||
		    (ret = nand_read(nand, off + WARP_DRV_PRELOAD, &size,
				     (void *)(warp_drv_addr +
					      WARP_DRV_PRELOAD))) == 0) {
			size += WARP_DRV_PRELOAD;
			flush_cache(warp_drv_addr, size);
			return 0;
		}
	}

	printf("hibdrv read error %d\n", ret);
	return ret;
}

#endif

static int warp_nand_bmload(int saveno)
{
	int ret;
	unsigned long size, off;
	nand_info_t *nand = &nand_info[0];

	off = warp_nand_skipbad(nand, warp_savearea[saveno].bootflag_area,
		warp_savearea[saveno].bootflag_size);
	if (off == (unsigned long)-1)
		return 1;

	off += WARP_MODE_OFFSET;

	off = warp_nand_skipbad(nand, off, warp_savearea[saveno].bootflag_size);
	if (off == (unsigned long)-1)
		return 1;

	ret = nand_read(nand, off, &size, warp_bfaddr);
	if (ret != 0) {
		printf("bootmode read error %d\n", ret);
		return ret;
	}

	return 0;
}

static int warp_nand_bfload(int saveno)
{
	int ret;
	unsigned long size, off;
	nand_info_t *nand = &nand_info[0];

	off = warp_nand_skipbad(nand, warp_savearea[saveno].bootflag_area,
				warp_savearea[saveno].bootflag_size);
	if (off == (unsigned long)-1)
		return 1;

	size = WARP_BF_LEN;
	ret = nand_read(nand, off, &size, warp_bfaddr);
	if (ret != 0) {
		printf("bootflag read error %d\n", ret);
		return ret;
	}

	return 0;
}

static int warp_nand_bferase(int saveno)
{
	int ret;
	unsigned long off, end;
	nand_info_t *nand = &nand_info[0];

	off = warp_savearea[saveno].bootflag_area;
	end = off + warp_savearea[saveno].bootflag_size;
	printf("Warp!! bootflag clear NAND: 0x%08lx-0x%08lx\n", off, end - 1);

	while (off < end) {
		if (!nand_block_isbad(nand, off)) {
			if ((ret = nand_erase(nand, off, nand->erasesize)) != 0) {
				printf("bootflag erase error %d\n", ret);
				return ret;
			}
		}
		off += nand->erasesize;
	}
	return 0;
}

#endif /* CONFIG_WARP_NAND */

#if defined(CONFIG_WARP_ATA) || defined(CONFIG_WARP_SD)

#if (CONFIG_WARP_DRV_DEV & WARP_DEV_MASK) == WARP_DEV_ATA || \
    (CONFIG_WARP_DRV_DEV & WARP_DEV_MASK) == WARP_DEV_SD

static int warp_dev_drvload(disk_partition_t * info, block_dev_desc_t * dev_desc)
{
	int ret;
	unsigned long size, off, blk;

	off = info->start + warp_drv_area;
	if ((ret = dev_desc->block_read(dev_desc->dev, off, 1,
					(void *)warp_drv_addr)) >= 0) {
		if (*(int *)(warp_drv_addr + WARP_HEADER_ID) != WARP_ID_DRIVER)
			return 1;
		size = *(int *)(warp_drv_addr + WARP_HEADER_COPY_SIZE);
		blk = (size - 1) / dev_desc->blksz;
		ret = dev_desc->block_read(dev_desc->dev, off + 1, blk,
					   (void *)(warp_drv_addr + dev_desc->blksz))
		if (blk <= 0 || ret >= 0) {
			flush_cache(warp_drv_addr, size);
			return 0;
		}
	}

	printf("hibdrv read error %d\n", ret);
	return ret;
}

#endif

static int warp_dev_bfload(disk_partition_t * info, block_dev_desc_t * dev_desc,
			   int saveno)
{
	int ret;
	unsigned long off;

	off = info->start + warp_savearea[saveno].bootflag_area;
	ret = dev_desc->block_read(dev_desc->dev, off, 1, warp_bfaddr);
	if (ret != 1) {
		printf("bootflag read error %d\n", ret);
		return ret;
	}

	return 0;
}

static int warp_dev_bferase(disk_partition_t * info,
			    block_dev_desc_t * dev_desc,
			    int saveno,
			    const char *name)
{
#if U_BOOT_VERSION_CODE >= U_BOOT_VER(1,3,0)
	int ret;
	unsigned long off;
	int lun, part;
	char *buf[512];

	if (!dev_desc->block_write) {
		printf("not support\n");
		return 0;
	}

	memset(buf, 0, 512);
	lun = WARP_DEV_TO_LUN(warp_savearea[saveno].bootflag_dev);
	part = WARP_DEV_TO_PART(warp_savearea[saveno].bootflag_dev);
	off = info->start + warp_savearea[saveno].bootflag_area;
	printf("Warp!! bootflag clear %s%d part:%d offs:0x%08x (sect:0x%08lx)\n",
	     name, lun, part, warp_savearea[saveno].bootflag_area, off);

	ret = dev_desc->block_write(dev_desc->dev, off, 1, (void *)buf);
	if (ret != 1) {
		printf("bootflag erase error %d\n", ret);
		return ret;
	}
#else
	printf("not support\n");
#endif
	return 0;
}

#endif /* CONFIG_WARP_ATA || CONFIG_WARP_SD */

#ifdef CONFIG_WARP_ATA

#if U_BOOT_VERSION_CODE < U_BOOT_VER(1,3,3)
#error "ATA: not support"
#endif

#include <sata.h>

extern block_dev_desc_t sata_dev_desc[];

static int warp_ata_init(int dev, disk_partition_t * info,
			 block_dev_desc_t ** dev_desc)
{
	int ret;
	u32 lun, part;
	block_dev_desc_t *sata_get_dev(int dev);

	lun = WARP_DEV_TO_LUN(dev);
	part = WARP_DEV_TO_PART(dev);

	if (sata_dev_desc[lun].if_type != IF_TYPE_SATA) {
		memset(&sata_dev_desc[lun], 0, sizeof(struct block_dev_desc));
		sata_dev_desc[lun].if_type = IF_TYPE_SATA;
		sata_dev_desc[lun].dev = lun;
		sata_dev_desc[lun].part_type = PART_TYPE_UNKNOWN;
		sata_dev_desc[lun].type = DEV_TYPE_HARDDISK;
		sata_dev_desc[lun].lba = 0;
		sata_dev_desc[lun].blksz = 512;
		sata_dev_desc[lun].block_read = sata_read;
		sata_dev_desc[lun].block_write = sata_write;

		if ((ret = init_sata(lun)))
			return ret;
		if ((ret = scan_sata(lun)))
			return ret;
		if ((sata_dev_desc[lun].lba > 0) && (sata_dev_desc[lun].blksz > 0))
			init_part(&sata_dev_desc[lun]);
	}

	if ((*dev_desc = sata_get_dev(lun)) == NULL) {
		printf("device %d not found\n", lun);
		return -1;
	}

	if (part == 0) {
		info->start = 0;
		return 0;
	}

	if ((ret = get_partition_info(*dev_desc, part, info)) != 0) {
		printf("partition %d:%d not found\n", lun, part);
		return ret;
	}

	return 0;
}

#if (CONFIG_WARP_DRV_DEV & WARP_DEV_MASK) == WARP_DEV_ATA

static int warp_ata_drvload(void)
{
	int ret;
	block_dev_desc_t *dev_desc;
	disk_partition_t info;

	ret = warp_ata_init(CONFIG_WARP_DRV_DEV, &info, &dev_desc);
	if (ret != 0)
		return ret;

	return warp_dev_drvload(&info, dev_desc);
}

#endif

static int warp_ata_bfload(int saveno)
{
	int ret;
	block_dev_desc_t *dev_desc;
	disk_partition_t info;

	ret = warp_ata_init(warp_savearea[saveno].bootflag_dev, &info, &dev_desc);
	if (ret != 0)
		return ret;

	return warp_dev_bfload(&info, dev_desc, saveno);
}

static int warp_ata_bferase(int saveno)
{
	int ret;
	block_dev_desc_t *dev_desc;
	disk_partition_t info;

	ret = warp_ata_init(warp_savearea[saveno].bootflag_dev, &info, &dev_desc);
	if (ret != 0)
		return ret;

	return warp_dev_bferase(&info, dev_desc, saveno, "ATA");
}

#endif /* CONFIG_WARP_ATA */

#ifdef CONFIG_WARP_SD

#include <part.h>
#include <mmc.h>

static int warp_sd_init(int dev, disk_partition_t * info,
			block_dev_desc_t ** dev_desc)
{
	int ret;
	u32 lun, part;
	block_dev_desc_t *mmc_get_dev(int dev);
#ifdef CONFIG_GENERIC_MMC
	struct mmc *mmc;
#endif

	lun = WARP_DEV_TO_LUN(dev);
	part = WARP_DEV_TO_PART(dev);

#ifdef CONFIG_GENERIC_MMC
	if (!(mmc = find_mmc_device(lun))) {
		printf("device %d not found\n", lun);
		return -1;
	}

	ret = mmc_init(mmc);
#else
#if U_BOOT_VERSION_CODE < U_BOOT_VER(2009,3,0)
	ret = mmc_init(0);
#else
	ret = mmc_legacy_init(0);
#endif
#endif

	if (ret != 0) {
		printf("No MMC card found\n");
		return ret;
	}

	if ((*dev_desc = mmc_get_dev(lun)) == NULL) {
		printf("device %d not found\n", lun);
		return -1;
	}

	if (part == 0) {
		info->start = 0;
		return 0;
	}

	if ((ret = get_partition_info(*dev_desc, part, info)) != 0) {
		printf("partition %d:%d not found\n", lun, part);
		return ret;
	}

	return 0;
}

#if (CONFIG_WARP_DRV_DEV & WARP_DEV_MASK) == WARP_DEV_SD

static int warp_sd_drvload(void)
{
	int ret;
	block_dev_desc_t *dev_desc;
	disk_partition_t info;

	ret = warp_sd_init(CONFIG_WARP_DRV_DEV, &info, &dev_desc);
	if (ret != 0)
		return ret;

	return warp_dev_drvload(&info, dev_desc);
}

#endif

static int warp_sd_bfload(int saveno)
{
	int ret;
	block_dev_desc_t *dev_desc;
	disk_partition_t info;

	ret = warp_sd_init(warp_savearea[saveno].bootflag_dev, &info, &dev_desc);
	if (ret != 0)
		return ret;

	return warp_dev_bfload(&info, dev_desc, saveno);
}

static int warp_sd_bferase(int saveno)
{
	int ret;
	block_dev_desc_t *dev_desc;
	disk_partition_t info;

	ret = warp_sd_init(warp_savearea[saveno].bootflag_dev, &info, &dev_desc);
	if (ret != 0)
		return ret;

	return warp_dev_bferase(&info, dev_desc, saveno, "SD");
}

#endif /* CONFIG_WARP_SD */

int warp_drvload(void)
{
	int ret = 0;

#if (CONFIG_WARP_DRV_DEV & WARP_DEV_MASK) == WARP_DEV_NOR
	ret = warp_nor_drvload();
#elif (CONFIG_WARP_DRV_DEV & WARP_DEV_MASK) == WARP_DEV_NAND
	ret = warp_nand_drvload();
#elif (CONFIG_WARP_DRV_DEV & WARP_DEV_MASK) == WARP_DEV_ATA
	ret = warp_ata_drvload();
#elif (CONFIG_WARP_DRV_DEV & WARP_DEV_MASK) == WARP_DEV_SD
	ret = warp_sd_drvload();
#elif (CONFIG_WARP_DRV_DEV & WARP_DEV_MASK) == WARP_DEV_EXT
	ret = warp_extdrv_drvload();
#endif

	return ret;
}

int warp_check_bootargs(void)
{
	int ret;
	unsigned long long addr, len;
	char *ptr;
	char *media_name = "hinand";
	char tag_buf[WARP_TAG_SIZE];

	const char *bootargs = getenv("bootargs");
	if (!bootargs) {
		ret = 1;
		goto failed;
	}

	if (NULL == (ptr = strstr(bootargs, "mtdparts="))) {
		ret = 1;
		goto failed;
	}

	ptr += strlen("mtdparts=");

	if (find_flash_part(ptr, media_name, "warpdrv", &addr, &len)) {
		warp_drv_area = (unsigned int)addr;
		warp_drv_size = (unsigned int)len;
	} else {
		ret = 1;
		goto failed;
	}

	if (find_flash_part(ptr, media_name, "warpflag", &addr, &len)) {
		warp_flag_area = (unsigned int)addr;
		warp_flag_size = (unsigned int)len;
	} else {
		ret = 1;
		goto failed;
	}

	if (find_flash_part(ptr, media_name, "warpdata", &addr, &len)) {
		warp_data_area = (unsigned int)addr;
		warp_data_size = (unsigned int)len;
	} else {
		ret = 1;
		goto failed;
	}

	warp_savearea[0].bootflag_dev = WARP_DEV(NAND, 0, 0);
	warp_savearea[0].bootflag_area = warp_flag_area;
	warp_savearea[0].bootflag_size = warp_flag_size;

	/* init loadaddress */
	warp_drv_addr = reserve_mem_alloc(WARP_HIBDRV_SIZE, NULL);
	if (!warp_drv_addr) {
		ret = 1;
		goto failed;
	}
	warp_drv_addr &= 0xfff00000;
	memset(tag_buf, 0, sizeof(tag_buf));
	snprintf(tag_buf, sizeof(tag_buf), "warp_drv_addr=%x", warp_drv_addr);
	set_param_data("wpaddr", tag_buf, sizeof(tag_buf));

#if CONFIG_SHOW_WARP_INFO
	printf("Warp!! drv  phyaddr 0x%X\n", warp_drv_addr);
	printf("Warp!! drv  start 0x%X, size 0x%X\n", warp_drv_area, warp_drv_size);
	printf("Warp!! flag start 0x%X, size 0x%X\n", warp_flag_area, warp_flag_size);
	printf("Warp!! data start 0x%X, size 0x%X\n", warp_data_area, warp_data_size);
#endif
	check_boot_ok = 1;

	return 0;

failed:
	return ret;
}

int warp_checkboot(int saveno)
{
	int ret;
	char *str;

	ret = warp_check_bootargs();
	if (ret)
		return 1;

	if (saveno < 0) {
		if ((str = getenv("warpsaveno")))
			saveno = simple_strtoul(str, NULL, 10);
		else
			saveno = warp_saveno;
	}

	if (saveno < 0 || saveno >= WARP_SAVEAREA_NUM) {
		printf("Illegal saveno %d\n", saveno);
		return 1;
	}

	if ((ret = warp_drvload()) != 0)
		return ret;

	warp_bfaddr = (void *)warp_drv_addr +
	    *(int *)(warp_drv_addr + WARP_HEADER_COPY_SIZE);
#ifdef CONFIG_WARP_NAND
	if ((ret = warp_nand_bmload(saveno)) != 0){
		printf("load boot mode flags error\n");
		return ret;
	}
#endif
	printf("Warp mode :%x\n", *(unsigned int *)warp_bfaddr);

	if (*(unsigned int *)warp_bfaddr != WARP_MODE) {
		return 1;
	} else {
		char tag_buf[WARP_TAG_SIZE];
		unsigned int boot_mode = NORMAL_MODE;

		boot_mode = *(unsigned int *)warp_bfaddr;
		memset(tag_buf, 0, sizeof(tag_buf));
		snprintf(tag_buf, sizeof(tag_buf), "warp_boot_mode=%x", boot_mode);
		set_param_data("wpmode", tag_buf, sizeof(tag_buf));
		printf("set wpmode\n");
	}

#ifdef CONFIG_WARP_NOR
	if ((warp_savearea[saveno].bootflag_dev & WARP_DEV_MASK) ==
	    WARP_DEV_NOR)
		if ((ret = warp_nor_bfload(saveno)) != 0)
			return ret;
#endif

#ifdef CONFIG_WARP_NAND
	if ((warp_savearea[saveno].bootflag_dev & WARP_DEV_MASK) ==
	    WARP_DEV_NAND)
		if ((ret = warp_nand_bfload(saveno)) != 0)
			return ret;
#endif

#ifdef CONFIG_WARP_ATA
	if ((warp_savearea[saveno].bootflag_dev & WARP_DEV_MASK) ==
	    WARP_DEV_ATA)
		if ((ret = warp_ata_bfload(saveno)) != 0)
			return ret;
#endif

#ifdef CONFIG_WARP_SD
	if ((warp_savearea[saveno].bootflag_dev & WARP_DEV_MASK) == WARP_DEV_SD)
		if ((ret = warp_sd_bfload(saveno)) != 0)
			return ret;
#endif

#ifdef CONFIG_WARP_EXTDRV
	if ((warp_savearea[saveno].bootflag_dev & WARP_DEV_MASK) ==
	    WARP_DEV_EXT)
		if ((ret = warp_extdrv_bfload(saveno)) != 0)
			return ret;
#endif

#ifdef CONFIG_WARP_USERDRV
	if ((warp_savearea[saveno].bootflag_dev & WARP_DEV_MASK) ==
	    WARP_DEV_USER)
		if ((ret = warp_userdrv_bfload(saveno)) != 0)
			return ret;
#endif

	if (*(unsigned int *)warp_bfaddr != WARP_ID_BOOTFLAG)
		return 1;

	return 0;
}

static void warp_fix(void)
{
	*(volatile unsigned int*)0xf8ccc000 = 0x1;
	*(volatile unsigned int*)0xf8ccc400 = 0x1;
}

int warp_boot(int saveno)
{
	int ret;
	int (*hibernate) (void);

	if ((ret = warp_checkboot(saveno)) != 0)
		return ret;

	warp_fix();
	hibernate = (void *)(warp_drv_addr + WARP_HEADER_HIBERNATE);
	ret = hibernate();
	printf("Warp!! error can not boot %d\n", ret);
	return ret;
}

static int do_warp(cmd_tbl_t * cmdtp, int flag,
		   int argc, char *CMD_CONST argv[])
{
	int saveno = warp_saveno;
	char *str = NULL;

	if (argc > 1)
		str = argv[1];
	else
		str = getenv("warpsaveno");
	if (str)
		saveno = simple_strtoul(str, NULL, 10);

	warp_boot(saveno);

	return 0;
}

static int do_clear_bootf(cmd_tbl_t * cmdtp, int flag,
			  int argc, char *CMD_CONST argv[])
{
	int ret = 0;
	int saveno = warp_saveno;
	char *str = NULL;

	if (!check_boot_ok)
		warp_check_bootargs();

	if (argc > 1)
		str = argv[1];
	else
		str = getenv("warpsaveno");
	if (str)
		saveno = simple_strtoul(str, NULL, 10);

	if (saveno < 0)
		saveno = CONFIG_WARP_SAVENO;;
	if (saveno < 0 || saveno >= WARP_SAVEAREA_NUM) {
		printf("Illegal saveno %d\n", saveno);
		return 1;
	}
#ifdef CONFIG_WARP_NOR
	if ((warp_savearea[saveno].bootflag_dev & WARP_DEV_MASK) == WARP_DEV_NOR)
		ret = warp_nor_bferase(saveno);
#endif

#ifdef CONFIG_WARP_NAND
	if ((warp_savearea[saveno].bootflag_dev & WARP_DEV_MASK) == WARP_DEV_NAND)
		ret = warp_nand_bferase(saveno);
#endif

#ifdef CONFIG_WARP_ATA
	if ((warp_savearea[saveno].bootflag_dev & WARP_DEV_MASK) == WARP_DEV_ATA)
		ret = warp_ata_bferase(saveno);
#endif

#ifdef CONFIG_WARP_SD
	if ((warp_savearea[saveno].bootflag_dev & WARP_DEV_MASK) == WARP_DEV_SD)
		ret = warp_sd_bferase(saveno);
#endif

#ifdef CONFIG_WARP_EXTDRV
	if ((warp_savearea[saveno].bootflag_dev & WARP_DEV_MASK) == WARP_DEV_EXT)
		ret = warp_extdrv_bferase(saveno);
#endif

#ifdef CONFIG_WARP_USERDRV
	if ((warp_savearea[saveno].bootflag_dev & WARP_DEV_MASK) == WARP_DEV_USER)
		ret = warp_userdrv_bferase(saveno);
#endif

	return ret;
}

U_BOOT_CMD(warp, 2, 0, do_warp,
#if U_BOOT_VERSION_CODE < U_BOOT_VER(2009,3,0)
	   "warp    - Warp!! boot\n",
#else
	   "Warp!! boot",
#endif
	   "[saveno]"
#if U_BOOT_VERSION_CODE < U_BOOT_VER(2009,8,0)
	   "\n"
#endif
);

U_BOOT_CMD(clearwarp, 2, 0, do_clear_bootf,
#if U_BOOT_VERSION_CODE < U_BOOT_VER(2009,3,0)
	   "clearwarp - clear Warp!! bootflag\n",
#else
	   "clear Warp!! bootflag",
#endif
	   "[saveno]"
#if U_BOOT_VERSION_CODE < U_BOOT_VER(2009,8,0)
	   "\n"
#endif
);

#endif /* CONFIG_WARP */
