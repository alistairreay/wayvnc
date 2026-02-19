/*
 * Copyright (c) 2019 Andri Yngvason
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

#pragma once

#include <stddef.h>
#include <stdint.h>
#include <assert.h>

struct wv_vec {
	void* data;
	size_t len;
	size_t cap;
};

static inline void wv_vec_clear(struct wv_vec* self)
{
	self->len = 0;
}

int wv_vec_init(struct wv_vec*, size_t cap);
void wv_vec_destroy(struct wv_vec*);

int wv_vec_reserve(struct wv_vec*, size_t cap);

void wv_vec_bzero(struct wv_vec*);

int wv_vec_assign(struct wv_vec*, const void* data, size_t size);
int wv_vec_append(struct wv_vec*, const void* data, size_t size);
void* wv_vec_append_zero(struct wv_vec*, size_t size);

static inline void wv_vec_fast_append_8(struct wv_vec* self, uint8_t value)
{
	assert(self->len < self->cap);
	((uint8_t*)self->data)[self->len++] = value;
}

static inline void wv_vec_fast_append_32(struct wv_vec* self, uint32_t value)
{
	assert(self->len + sizeof(value) <= self->cap);
	assert(self->len % sizeof(value) == 0);
	uint32_t* p = (uint32_t*)((uint8_t*)self->data + self->len);
	*p = value;
	self->len += sizeof(value);
}

#define wv_vec_for(elem, self)                                                 \
	for (elem = (self)->data;                                              \
             ((ptrdiff_t)elem - (ptrdiff_t)(self)->data) < (ptrdiff_t)(self)->len;\
	     ++elem)

#define wv_vec_for_tail(elem, self)                                            \
	for (elem = (self)->data, ++elem;                                      \
	     ((ptrdiff_t)elem - (ptrdiff_t)(self)->data) < (ptrdiff_t)(self)->len;\
	     ++elem)

#define wv_vec_for_ptr(elem, self)                                             \
	__typeof__(elem)* ptr_;                                                \
	wv_vec_for(ptr_, self)                                                 \
                if ((elem = *ptr_))
