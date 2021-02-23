/* Includes */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/mm.h>
#include <asm/io.h>
#include <asm/uaccess.h>

#include <drvfpgasoc.h>

/* Module information */
MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Kohei Nagasu <kohei@lcarsnet.pgw.jp>");
MODULE_DESCRIPTION("Driver to access FPGA fabric.");

/* Macros */
#define FPGASOC_DRIVER_NAME         "fpgasoc"
#define FPGASOC_MINOR_BASE          (0)
#define FPGASOC_MINOR_LENGTH        (1)
#define FPGASOC_PHYSADDR_LWFPGASLVS ((unsigned long)0xFF200000UL)
#define FPGASOC_SIZE_LWFPGASLVS     ((unsigned long)0x00200000UL)
#define FPGASOC_ACCSSIZE_IOCX8      ((unsigned long)1UL)
#define FPGASOC_ACCSSIZE_IOCX16     ((unsigned long)2UL)
#define FPGASOC_ACCSSIZE_IOCX32     ((unsigned long)4UL)

/* Macro functions */
#define fpgasoc_errmsg(...) pr_err(FPGASOC_DRIVER_NAME ": " __VA_ARGS__)
#define fpgasoc_wrnmsg(...) pr_warn(FPGASOC_DRIVER_NAME ": " __VA_ARGS__)
#define fpgasoc_infmsg(...) pr_info(FPGASOC_DRIVER_NAME ": " __VA_ARGS__)
#define fpgasoc_dbgmsg(...) \
do { \
	if (fpgasoc_isdbg) { \
		printk(KERN_DEBUG FPGASOC_DRIVER_NAME ": " __VA_ARGS__); \
	} \
} while(0)

#define FPGASOC_IOCTL_CMDID(cmd) ((unsigned int)_IOC_NR(cmd) - (unsigned int)1U)

/* Types */
typedef long (*fpgasoc_ioctl_cmdfunc_t)(const fpgasoc_ioctlarg_t * const);

/* System calls prototypes */
static int fpgasoc_open(struct inode *inode, struct file *file);
static int fpgasoc_close(struct inode *inode, struct file *file);
static int fpgasoc_mmap(struct file *file, struct vm_area_struct *vma);
static long fpgasoc_ioctl(struct file *file, unsigned int cmd, unsigned long arg);

/* Ohter prototypes */
static long fpgasoc_ioctl_iocr8(const fpgasoc_ioctlarg_t * const karg);
static long fpgasoc_ioctl_iocw8(const fpgasoc_ioctlarg_t * const karg);
static long fpgasoc_ioctl_iocr16(const fpgasoc_ioctlarg_t * const karg);
static long fpgasoc_ioctl_iocw16(const fpgasoc_ioctlarg_t * const karg);
static long fpgasoc_ioctl_iocr32(const fpgasoc_ioctlarg_t * const karg);
static long fpgasoc_ioctl_iocw32(const fpgasoc_ioctlarg_t * const karg);

/* Constants */
static const struct file_operations fpgasoc_fops = {
	.open = fpgasoc_open,
	.release = fpgasoc_close,
	.mmap = fpgasoc_mmap,
	.unlocked_ioctl = fpgasoc_ioctl,
	.compat_ioctl = fpgasoc_ioctl,
	.read = NULL,
	.write = NULL,
};

static const fpgasoc_ioctl_cmdfunc_t fpgasoc_ioctl_cmdtbl[FPGASOC_IOC_MAXNR] = {
	[FPGASOC_IOCTL_CMDID(FPGASOC_IOCR8)]  = fpgasoc_ioctl_iocr8,
	[FPGASOC_IOCTL_CMDID(FPGASOC_IOCW8)]  = fpgasoc_ioctl_iocw8,
	[FPGASOC_IOCTL_CMDID(FPGASOC_IOCR16)] = fpgasoc_ioctl_iocr16,
	[FPGASOC_IOCTL_CMDID(FPGASOC_IOCW16)] = fpgasoc_ioctl_iocw16,
	[FPGASOC_IOCTL_CMDID(FPGASOC_IOCR32)] = fpgasoc_ioctl_iocr32,
	[FPGASOC_IOCTL_CMDID(FPGASOC_IOCW32)] = fpgasoc_ioctl_iocw32,
};

/* Valiables */
static unsigned int fpgasoc_major;
static struct cdev fpgasoc_cdev;
static struct class *fpgasoc_class = NULL;
static void *fpgasoc_ioptr = NULL;

static _Bool fpgasoc_isdbg = false;
module_param(fpgasoc_isdbg, bool, S_IRUGO|S_IWUSR);

/* system calls */
static int fpgasoc_open(struct inode *inode, struct file *file)
{
	fpgasoc_dbgmsg("Execute open\n");
	return 0;
}

static int fpgasoc_close(struct inode *inode, struct file *file)
{
	fpgasoc_dbgmsg("Execute close\n");
	return 0;
}

/* THIS IS BUGGY */
static int fpgasoc_mmap(struct file *file, struct vm_area_struct *vma)
{
	unsigned long offset = vma->vm_pgoff << PAGE_SHIFT;
	unsigned long phys_start = FPGASOC_PHYSADDR_LWFPGASLVS + offset;
	unsigned long phys_pfn = phys_start >> PAGE_SHIFT;
	unsigned long vsize = vma->vm_end - vma->vm_start;
	unsigned long psize = (unsigned long)FPGASOC_SIZE_LWFPGASLVS;

	fpgasoc_wrnmsg("[ WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING ]\n");
	fpgasoc_wrnmsg("[ WARNING     This implementation of mmap is BUGGY!!! Please use with caution.    WARNING ]\n");
	fpgasoc_wrnmsg("[ WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING WARNING ]\n");

	if (vsize > psize) {
		return -EINVAL;
	}


	remap_pfn_range(vma, vma->vm_start, phys_pfn, vsize, vma->vm_page_prot);

	fpgasoc_wrnmsg("Execute mmap (pyhs:0x%08lX-0x%08lX, virtual:0x%08lX-%08lX)\n",
	               phys_start, (phys_start + vsize), vma->vm_start, (vma->vm_start + vsize));

	return 0;
}

static long fpgasoc_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	_Bool isCmdValid = false;
	long retval = (long)0L;

	/* Check cmd's type bit-field and NR bit-field */
	if (
	    (_IOC_TYPE(cmd) == FPGASOC_IOC_MAGIC) &&
	    (_IOC_NR(cmd) <= FPGASOC_IOC_MAXNR) &&
	    (
	     ((_IOC_DIR(cmd) & _IOC_READ) != 0) ||
	     ((_IOC_DIR(cmd) & _IOC_WRITE) != 0)
	    )
	) {
		int isAccessok = access_ok((void __user *)arg, _IOC_SIZE(cmd));
		if (isAccessok == (int)1) {
			isCmdValid = true;

		} else {
			fpgasoc_dbgmsg("Execute ioctl with error (EFAULT)\n");
			retval = -EFAULT;
		}

	} else {
		retval = -ENOTTY;
		fpgasoc_dbgmsg("Execute ioctl with error (ENOTTY)\n");
	}

	/* Execute command process */
	if (isCmdValid) {
		fpgasoc_ioctlarg_t karg = {
			.offset = (unsigned long)0UL,
			.data = NULL,
		};
		const fpgasoc_ioctl_cmdfunc_t cmdfunc = fpgasoc_ioctl_cmdtbl[FPGASOC_IOCTL_CMDID(cmd)];

		/* Return value of __copy_from_user is not used. */
		/* In order to suppress from compiler warning.   */
		retval = raw_copy_from_user(&karg, (fpgasoc_ioctlarg_t __user *)arg,
		                            (unsigned long)sizeof(fpgasoc_ioctlarg_t)); /* Get argument */

		/* Execute command */
		retval = cmdfunc(&karg);
	}

	return retval;
}

/* Scheduled functions */
static int __init fpgasoc_init(void)
{
	int result;
	dev_t dev;
	struct resource *ret_mem_region;

	fpgasoc_infmsg("Start Initialization\n");

	/* Request i/o memory of LWFPGASLVS */
	ret_mem_region = request_mem_region(FPGASOC_PHYSADDR_LWFPGASLVS, FPGASOC_SIZE_LWFPGASLVS, 
	                                    FPGASOC_DRIVER_NAME);
	if (ret_mem_region == NULL) {
		fpgasoc_errmsg("Error Initialization (request_mem_region)\n");
		return -1;
	}

	/* Remapping i/o memory of LWFPGASLVS */
	fpgasoc_ioptr = ioremap_nocache(FPGASOC_PHYSADDR_LWFPGASLVS, FPGASOC_SIZE_LWFPGASLVS);
	if (fpgasoc_ioptr == NULL) {
		fpgasoc_errmsg("Error Initialization (ioremap_nocache)\n");
		release_mem_region(FPGASOC_PHYSADDR_LWFPGASLVS, FPGASOC_SIZE_LWFPGASLVS);
		return -1;
	}

	/* Allocate major number */
	result = alloc_chrdev_region(&dev, (unsigned int)FPGASOC_MINOR_BASE,
	                             (unsigned int)FPGASOC_MINOR_LENGTH, FPGASOC_DRIVER_NAME);
	if (result != 0) {
		fpgasoc_errmsg("Error Initalization (alloc_chrdev_region = %d)\n", result);
		iounmap(fpgasoc_ioptr);
		fpgasoc_ioptr = NULL;
		release_mem_region(FPGASOC_PHYSADDR_LWFPGASLVS, FPGASOC_SIZE_LWFPGASLVS);
		return -1;
	}

	/* Save major number */
	fpgasoc_major = MAJOR(dev);

	/* Initialize struct cdev and register table of syscall handler */
	cdev_init(&fpgasoc_cdev, &fpgasoc_fops);
	fpgasoc_cdev.owner = THIS_MODULE;

	/* Register this cdev to kernel */
	result = cdev_add(&fpgasoc_cdev, dev, (unsigned int)FPGASOC_MINOR_LENGTH);
	if (result != 0) {
		fpgasoc_errmsg("Error Initalization (cdev_add = %d)\n", result);
		unregister_chrdev_region(dev, (unsigned int)FPGASOC_MINOR_LENGTH);
		iounmap(fpgasoc_ioptr);
		fpgasoc_ioptr = NULL;
		release_mem_region(FPGASOC_PHYSADDR_LWFPGASLVS, FPGASOC_SIZE_LWFPGASLVS);
		return -1;
	}

	/* Register class of this device */
	fpgasoc_class = class_create(THIS_MODULE, FPGASOC_DRIVER_NAME);
	if (IS_ERR(fpgasoc_class)) {
		fpgasoc_errmsg("Error Initalization (class_create)\n");
		cdev_del(&fpgasoc_cdev);
		unregister_chrdev_region(dev, (unsigned int)FPGASOC_MINOR_LENGTH);
		iounmap(fpgasoc_ioptr);
		fpgasoc_ioptr = NULL;
		release_mem_region(FPGASOC_PHYSADDR_LWFPGASLVS, FPGASOC_SIZE_LWFPGASLVS);
		return -1;
	}

#if FPGASOC_MINOR_LENGTH == 1
	device_create(fpgasoc_class, NULL,
	              MKDEV(fpgasoc_major, (unsigned int)FPGASOC_MINOR_BASE),
	              NULL, FPGASOC_DRIVER_NAME);

#elif FPGASOC_MINOR_LENGTH > 1
	for (int i = (int)0; i < (int)FPGASOC_MINOR_LENGTH; i++) {
		int minor = (int)FPGASOC_MINOR_BASE + i;
		device_create(fpgasoc_class, NULL, MKDEV(fpgasoc_major, minor),
		              NULL, FPGASOC_DRIVER_NAME "%d", minor);
	}

#else
#error "FPGASOC_MINOR_LENGTH is invalid."
#endif

	fpgasoc_infmsg("Finished Initialization. FPGASOC is ready to action!!\n");

	return 0;
}

static void __exit fpgasoc_exit(void)
{
	dev_t dev = MKDEV(fpgasoc_major, (unsigned int)FPGASOC_MINOR_BASE);

	fpgasoc_infmsg("Start Finalization\n");

	/* Unregister class of this device */
#if FPGASOC_MINOR_LENGTH == 1
	device_destroy(fpgasoc_class,
	               MKDEV(fpgasoc_major, (unsigned int)FPGASOC_MINOR_BASE));

#elif FPGASOC_MINOR_LENGTH > 1
	for (int i = (int)0; i < (int)FPGASOC_MINOR_LENGTH; i++) {
		const int minor = (int)FPGASOC_MINOR_BASE + i;
		device_destroy(fpgasoc_class, MKDEV(fpgasoc_major, minor));
	}

#else
#error "FPGASOC_MINOR_LENGTH is invalid."
#endif

	class_destroy(fpgasoc_class);

	/* Unregister this device driver from kernel */
	cdev_del(&fpgasoc_cdev);

	/* Unregister major number used by this driver */
	unregister_chrdev_region(dev, (unsigned int)FPGASOC_MINOR_LENGTH);

	/* Unmapping I/O */
	iounmap(fpgasoc_ioptr);
	fpgasoc_ioptr = NULL;

	/* Release memory region of LWFPGASLVS */
	release_mem_region(FPGASOC_PHYSADDR_LWFPGASLVS, FPGASOC_SIZE_LWFPGASLVS);

	fpgasoc_infmsg("Finished Finalization. Have a nice day!\n");
}

/* Register initialize/exit functions */
module_init(fpgasoc_init);
module_exit(fpgasoc_exit);

/* Subfunctions */
static long fpgasoc_ioctl_iocr8(const fpgasoc_ioctlarg_t * const karg)
{
	const void * const   accessptr   = fpgasoc_ioptr + karg->offset; /* Calc pointer to access */
	const unsigned long  absphysaddr = FPGASOC_PHYSADDR_LWFPGASLVS + karg->offset;
	long retval = (long)0L;

	if ((karg->offset + FPGASOC_ACCSSIZE_IOCX8) <= FPGASOC_SIZE_LWFPGASLVS) {
		const uint8_t rdata = (uint8_t)ioread8((void __iomem *)accessptr);

		retval = put_user(rdata, (uint8_t __user *)karg->data);
		fpgasoc_dbgmsg("Execute ioctl (cmd = IOCR8, addr = 0x%08lX, rdata = 0x%02X)\n",
		               absphysaddr, rdata);

	} else {
		retval = -ENOTTY;
		fpgasoc_dbgmsg("Execute ioctl with error (ENOTTY)\n");
	}

	return retval;
}

static long fpgasoc_ioctl_iocw8(const fpgasoc_ioctlarg_t * const karg)
{
	const void * const   accessptr   = fpgasoc_ioptr + karg->offset; /* Calc pointer to access */
	const unsigned long  absphysaddr = FPGASOC_PHYSADDR_LWFPGASLVS + karg->offset;
	long retval = (long)0L;

	if ((karg->offset + FPGASOC_ACCSSIZE_IOCX8) <= FPGASOC_SIZE_LWFPGASLVS) {
		uint8_t wdata = (uint8_t)0U;
		retval = get_user(wdata, (uint8_t __user *)karg->data);

		if (retval == (unsigned long)0UL) {
			iowrite8((u8)wdata, (void __iomem *)accessptr);
			fpgasoc_dbgmsg("Execute ioctl (cmd = IOCW8, addr = 0x%08lX, wdata = 0x%02X)\n",
			               absphysaddr, wdata);
		}

	} else {
		retval = -ENOTTY;
		fpgasoc_dbgmsg("Execute ioctl with error (ENOTTY)\n");
	}

	return retval;
}

static long fpgasoc_ioctl_iocr16(const fpgasoc_ioctlarg_t * const karg)
{
	const void * const   accessptr   = fpgasoc_ioptr + karg->offset; /* Calc pointer to access */
	const unsigned long  absphysaddr = FPGASOC_PHYSADDR_LWFPGASLVS + karg->offset;
	long retval = (long)0L;

	if ((karg->offset + FPGASOC_ACCSSIZE_IOCX16) <= FPGASOC_SIZE_LWFPGASLVS) {
		const uint16_t rdata = (uint16_t)ioread16((void __iomem *)accessptr);

		retval = put_user(rdata, (uint16_t __user *)karg->data);
		fpgasoc_dbgmsg("Execute ioctl (cmd = IOCR16, addr = 0x%08lX, rdata = 0x%04X)\n",
		               absphysaddr, rdata);

	} else {
		retval = -ENOTTY;
		fpgasoc_dbgmsg("Execute ioctl with error (ENOTTY)\n");
	}

	return retval;
}

static long fpgasoc_ioctl_iocw16(const fpgasoc_ioctlarg_t * const karg)
{
	const void * const   accessptr   = fpgasoc_ioptr + karg->offset; /* Calc pointer to access */
	const unsigned long  absphysaddr = FPGASOC_PHYSADDR_LWFPGASLVS + karg->offset;
	long retval = (long)0L;

	if ((karg->offset + FPGASOC_ACCSSIZE_IOCX16) <= FPGASOC_SIZE_LWFPGASLVS) {
		uint16_t wdata = (uint16_t)0U;
		retval = get_user(wdata, (uint16_t __user *)karg->data);

		if (retval == (unsigned long)0UL) {
			iowrite16((u16)wdata, (void __iomem *)accessptr);
			fpgasoc_dbgmsg("Execute ioctl (cmd = IOCW16, addr = 0x%08lX, wdata = 0x%04X)\n",
					absphysaddr, wdata);
		}

	} else {
		retval = -ENOTTY;
		fpgasoc_dbgmsg("Execute ioctl with error (ENOTTY)\n");
	}

	return retval;
}

static long fpgasoc_ioctl_iocr32(const fpgasoc_ioctlarg_t * const karg)
{
	const void * const   accessptr   = fpgasoc_ioptr + karg->offset; /* Calc pointer to access */
	const unsigned long  absphysaddr = FPGASOC_PHYSADDR_LWFPGASLVS + karg->offset;
	long retval = (long)0L;

	if ((karg->offset + FPGASOC_ACCSSIZE_IOCX32) <= FPGASOC_SIZE_LWFPGASLVS) {
		const uint32_t rdata = (uint32_t)ioread32((void __iomem *)accessptr);

		retval = put_user(rdata, (uint32_t __user *)karg->data);
		fpgasoc_dbgmsg("Execute ioctl (cmd = IOCR32, addr = 0x%08lX, rdata = 0x%08X)\n",
		               absphysaddr, rdata);

	} else {
		retval = -ENOTTY;
		fpgasoc_dbgmsg("Execute ioctl with error (ENOTTY)\n");
	}

	return retval;
}
static long fpgasoc_ioctl_iocw32(const fpgasoc_ioctlarg_t * const karg)
{
	const void * const   accessptr   = fpgasoc_ioptr + karg->offset; /* Calc pointer to access */
	const unsigned long  absphysaddr = FPGASOC_PHYSADDR_LWFPGASLVS + karg->offset;
	long retval = (long)0L;

	if ((karg->offset + FPGASOC_ACCSSIZE_IOCX32) <= FPGASOC_SIZE_LWFPGASLVS) {
		uint32_t wdata = (uint32_t)0U;
		retval = get_user(wdata, (uint32_t __user *)karg->data);

		if (retval == (unsigned long)0UL) {
			iowrite32((u32)wdata, (void __iomem *)accessptr);
			fpgasoc_dbgmsg("Execute ioctl (cmd = IOCW32, addr = 0x%08lX, wdata = 0x%08X)\n",
					absphysaddr, wdata);
		}

	} else {
		retval = -ENOTTY;
		fpgasoc_dbgmsg("Execute ioctl with error (ENOTTY)\n");
	}

	return retval;
}

