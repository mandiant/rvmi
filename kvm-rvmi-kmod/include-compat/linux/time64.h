#ifndef _LINUX_TIME64_H
#define _LINUX_TIME64_H

#include <linux/time.h>

typedef __s64 time64_t;

/*
 * This wants to go into uapi/linux/time.h once we agreed about the
 * userspace interfaces.
 */
#if __BITS_PER_LONG == 64
# define timespec64 timespec
#else
struct timespec64 {
	time64_t	tv_sec;			/* seconds */
	long		tv_nsec;		/* nanoseconds */
};
#endif

#endif /* _LINUX_TIME64_H */
