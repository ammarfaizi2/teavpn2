// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2021  Ammar Faizi
 */
#ifndef TEAVPN2__MUTEX_H
#define TEAVPN2__MUTEX_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <teavpn2/common.h>

#define MUTEX_INIT		{PTHREAD_MUTEX_INITIALIZER, NULL}
#define DEFINE_MUTEX(VAR_NAME) 	struct tmutex VAR_NAME = MUTEX_INIT

struct tmutex {
	pthread_mutex_t			mutex;
#ifdef CONFIG_MUTEX_LEAK_ASSERT
	char				*__leak_ptr;
#endif	
};

static __always_inline int mutex_init(struct tmutex *m,
				      const pthread_mutexattr_t *attr)
{
	int ret;

	memset(m, 0, sizeof(*m));
	ret = pthread_mutex_init(&m->mutex, attr);
	if (unlikely(ret)) {
		ret = errno;
		pr_err("pthread_mutex_init(): " PRERF, PREAR(ret));
		return -ret;
	}

#ifdef CONFIG_MUTEX_LEAK_ASSERT
	m->__leak_ptr = malloc(1);
	if (unlikely(!m->__leak_ptr)) {
		panic("mutex_init(): Cannot init __leak_ptr");
		__builtin_unreachable();
	}
	m->__leak_ptr[0] = 0;
#endif
	return ret;
}

static __always_inline int mutex_lock(struct tmutex *m)
{
	return pthread_mutex_lock(&m->mutex);
}

static __always_inline int mutex_unlock(struct tmutex *m)
{
	return pthread_mutex_unlock(&m->mutex);
}

static __always_inline int mutex_trylock(struct tmutex *m)
{
	return pthread_mutex_trylock(&m->mutex);
}

static __always_inline int mutex_destroy(struct tmutex *m)
{
	int ret;

	ret = pthread_mutex_destroy(&m->mutex);
#ifdef CONFIG_MUTEX_LEAK_ASSERT
	free(m->__leak_ptr);
#endif
	memset(m, 0, sizeof(*m));
	return ret;
}

#endif /* #ifndef TEAVPN2__MUTEX_H */
