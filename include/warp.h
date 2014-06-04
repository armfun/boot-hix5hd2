/*
 * Warp!! common define  Rev. 4.0.2
 *
 */

#define WARP_HEADER_ID          0x00
#define WARP_HEADER_COPY_SIZE   0x04
#define WARP_HEADER_DRV_SIZE    0x08
#define WARP_HEADER_VERSION     0x0c
#define WARP_HEADER_SNAPSHOT    0x20
#define WARP_HEADER_HIBERNATE   0x28
#define WARP_HEADER_SWITCH      0x30

#define WARP_ID_DRIVER          0x44483457      /* W4HD */
#define WARP_ID_BOOTFLAG        0x46423457      /* W4BF */

#define WARP_PART_SHIFT         0
#define WARP_LUN_SHIFT          8
#define WARP_DEV_SHIFT          16

#define WARP_PART_MASK          (0xff << WARP_PART_SHIFT)
#define WARP_LUN_MASK           (0xff << WARP_LUN_SHIFT)
#define WARP_DEV_MASK           (0xff << WARP_DEV_SHIFT)

#define WARP_DEV_NOR            (0x01 << WARP_DEV_SHIFT)
#define WARP_DEV_NAND           (0x02 << WARP_DEV_SHIFT)
#define WARP_DEV_ATA            (0x03 << WARP_DEV_SHIFT)
#define WARP_DEV_SD             (0x04 << WARP_DEV_SHIFT)
#define WARP_DEV_MEM            (0x05 << WARP_DEV_SHIFT)
#define WARP_DEV_USER           (0x7e << WARP_DEV_SHIFT)
#define WARP_DEV_EXT            (0x7f << WARP_DEV_SHIFT)

#define WARP_DEV(dev, lun, part)        (WARP_DEV_##dev | \
                                         ((lun) << WARP_LUN_SHIFT) | \
                                         ((part) << WARP_PART_SHIFT))

#ifndef WARP_LUN_CONV
#define WARP_LUN_CONV(dev)      (dev)
#endif

#define WARP_DEV_TO_LUN(dev)    WARP_LUN_CONV(((dev) & WARP_LUN_MASK) >> \
                                              WARP_LUN_SHIFT)
#define WARP_DEV_TO_PART(dev)   (((dev) & WARP_PART_MASK) >> WARP_PART_SHIFT)

#define WARP_BF_LEN             0x100

#define WARP_SAVEAREA_NUM       (sizeof(warp_savearea) / \
                                 sizeof(struct warp_savearea))

#define WARP_DRV_PRELOAD        4096

struct warp_savearea {
	unsigned int bootflag_dev;
	unsigned int bootflag_area;
	unsigned int bootflag_size;
};

extern struct warp_savearea warp_savearea[];

extern int warp_saveno;

extern void *warp_bfaddr;

int warp_drvload(void);
int warp_checkboot(int saveno);
int warp_boot(int saveno);