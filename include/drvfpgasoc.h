#ifndef DRVFPGASOC_H
#define DRVFPGASOC_H

#include <linux/ioctl.h>

/* Type of argument */
typedef struct {
	unsigned long offset; /*!< Base offset to access */
	void          *data;  /*!< Pointer of read/written data */
} fpgasoc_ioctlarg_t;

/* Definition of command for ioctl */
#define FPGASOC_IOC_MAGIC 'X'

#define FPGASOC_IOCR8  (_IOR(FPGASOC_IOC_MAGIC, 1, fpgasoc_ioctlarg_t))
#define FPGASOC_IOCW8  (_IOW(FPGASOC_IOC_MAGIC, 2, fpgasoc_ioctlarg_t))
#define FPGASOC_IOCR16 (_IOR(FPGASOC_IOC_MAGIC, 3, fpgasoc_ioctlarg_t))
#define FPGASOC_IOCW16 (_IOW(FPGASOC_IOC_MAGIC, 4, fpgasoc_ioctlarg_t))
#define FPGASOC_IOCR32 (_IOR(FPGASOC_IOC_MAGIC, 5, fpgasoc_ioctlarg_t))
#define FPGASOC_IOCW32 (_IOW(FPGASOC_IOC_MAGIC, 6, fpgasoc_ioctlarg_t))

#define FPGASOC_IOC_MAXNR (6)

#endif

