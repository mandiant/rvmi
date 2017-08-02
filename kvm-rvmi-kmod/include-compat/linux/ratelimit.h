#define DEFINE_RATELIMIT_STATE(__name, a, b)	int (__name)

#define __ratelimit(__dummy) \
	({ *__dummy = *__dummy; printk_ratelimit(); })
