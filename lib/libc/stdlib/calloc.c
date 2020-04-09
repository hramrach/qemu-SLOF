/******************************************************************************
 * Copyright (c) 2020 IBM Corporation
 * All rights reserved.
 * This program and the accompanying materials
 * are made available under the terms of the BSD License
 * which accompanies this distribution, and is available at
 * http://www.opensource.org/licenses/bsd-license.php
 *
 * Contributors:
 *     IBM Corporation - initial implementation
 *****************************************************************************/


#include "stddef.h"
#include "stdlib.h"
#include "string.h"

void *calloc(size_t nmemb, size_t size) {
	size_t alloc_size;
	void *ret;
	if (__builtin_mul_overflow(nmemb, size, &alloc_size)) {
		return NULL;
	}

	ret = malloc(alloc_size);

	if (ret)
		memset(ret, 0, alloc_size);
	return ret;
}
