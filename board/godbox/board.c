
#include <config.h>
#include <common.h>
#include <asm/io.h>
#include <asm/sizes.h>
#include <asm/arch/platform.h>
#include <version.h>
#include <libfdt.h>
#include <malloc.h>

extern void eth_config_init(void);

static inline void delay (unsigned long loops)
{
	__asm__ volatile ("1:\n"
		"subs %0, %1, #1\n"
		"bne 1b":"=r" (loops):"0" (loops));
}

/*
 * Miscellaneous platform dependent initialisations
 */
int board_init (void)
{
	unsigned int size;
	unsigned int ddr_base;

	extern unsigned int _text_end;
	DECLARE_GLOBAL_DATA_PTR;

	gd->bd->bi_arch_number = MACH_TYPE_GODBOX;
	gd->bd->bi_boot_params = CFG_BOOT_PARAMS;
	gd->flags = 0;

	ddr_base = MEM_BASE_DDR;
	size = mmu_init(ddr_base, MEM_BASE_DDR, get_ddr_size());
	insert_ddr_layout(ddr_base, ddr_base + size, "page table");

	insert_ddr_layout(ddr_base + size,
		(unsigned int)(TEXT_BASE - CONFIG_BOOTHEAD_GAP
		- CONFIG_SYS_MALLOC_LEN - CONFIG_SYS_GBL_DATA_SIZE - 12),
		"stack");

	insert_ddr_layout((unsigned int)TEXT_BASE,
		(unsigned int)_text_end, ".text");

	insert_ddr_layout((unsigned int)_text_end,
		(unsigned int)_bss_end, "data");

	return 0;
}

int misc_init_r (void)
{
	const char *compatible;
	char *fdt;
	DECLARE_GLOBAL_DATA_PTR;
	int ret;

#ifdef CONFIG_RANDOM_ETHADDR
	random_init_r();
#endif

	eth_config_init();

	compatible = get_cpuinfo()->compatible;
	if (!compatible) {
		/* TODO: use a default compatible string? */
		return 0;
	}

	fdt = malloc(SZ_1K);
	if (!fdt) {
		printf("Error: malloc fdt failed!\n");
		return 0;
	}

	/* here we create a temp fdt which only include a compatible info */
	ret = fdt_create_empty_tree(fdt, SZ_1K);
	if (ret)
		printf("Error: create fdt(ret=%x)\n", ret);

	do_fixup_by_path_string(fdt, "/", "compatible", compatible);

	gd->fdt_blob = fdt;
	debug("fdt_blob = 0x%p\n", fdt);

	return (0);
}

static void display_info(void)
{
	char *str;
	unsigned int ca_vender = 0;

	ca_vender = get_ca_vendor();

	printf("Fastboot:      Version %d.%d.%d\n",
		VERSION, PATCHLEVEL, SUBLEVEL);
	printf("Build Date:    "__DATE__", "__TIME__"\n");

	get_cpu_version(&str);
	printf("CPU:           %s %s ", get_cpu_name(), str);
	if (ca_vender != CA_TYPE_NO_CA)
		printf("(ca 0x%04x)", ca_vender);
	printf("\n");
	get_bootmedia(&str, NULL);
	printf("Boot Media:    %s\n", str);
	printf("DDR Size:      %sB\n", ultohstr(get_ddr_size()));

	printf("\n");
}

int dram_init (void)
{
	DECLARE_GLOBAL_DATA_PTR;
	gd->bd->bi_dram[0].start = MEM_BASE_DDR;
	gd->bd->bi_dram[0].size  = get_ddr_size();

	display_info();
	return 0;
}

#ifdef CONFIG_OF_BOARD_SETUP
void ft_board_setup(void *fdt, bd_t *bd)
{
	char *version = CONFIG_SDKVERSION;
	int nodeoffset, err;
	extern unsigned int _blank_zone_start;
	extern unsigned int _blank_zone_end;
	int length = _blank_zone_end - _blank_zone_start;

	nodeoffset = fdt_path_offset (fdt, "/tags");
	/*
	 * If there is no "tags" node in the blob, create it.
	 */
	if (nodeoffset < 0) {
		/*
		 * Create a new node "/tags" (offset 0 is root level)
		 */
		nodeoffset = fdt_add_subnode(fdt, 0, "tags");
		if (nodeoffset < 0) {
			printf("WARNING: could not create /tags %s.\n",
				fdt_strerror(nodeoffset));
			return;
		}
	}

	err = fdt_setprop(fdt, nodeoffset,
			"sdkversion", version, strlen(version)+1);
	if (err < 0)
		printf("WARNING: could not set sdkversion %s.\n",
				fdt_strerror(err));

	err = fdt_setprop(fdt, nodeoffset,
			"bootreg", (void *)_blank_zone_start, length);
	if (err < 0)
		printf("WARNING: could not set bootreg %s.\n",
				fdt_strerror(err));
}
#endif
