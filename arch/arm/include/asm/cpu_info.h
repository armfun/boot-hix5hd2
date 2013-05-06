/******************************************************************************
 *    COPYRIGHT (C) 2013 Czyong. Hisilicon
 *    All rights reserved.
 * ***
 *    Create by Czyong 2013-02-27
 *
******************************************************************************/

#ifndef CPU_INFOH
#define CPU_INFOH
/******************************************************************************/

struct cpu_info_t {
	char        *name;
        /* dtb compatible info, used to select the suitable dtb,
        * must be same with the kernel's dtb compatible
        */
	char *compatible;
	long long    chipid;
	long long    chipid_mask;
	unsigned int max_ddr_size;

	unsigned int devs;

	int (*boot_media)(char **media);

	void (*get_clock)(unsigned int *cpu, unsigned int *timer);

	int (*get_cpu_version)(char **version);
};

/******************************************************************************/
#endif /* CPU_INFOH */
