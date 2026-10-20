/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef CPU_LIST_H
#define CPU_LIST_H
#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/* Linux per-CPU map values are packed in possible-CPU order, not CPU-ID order.
 * Parse sysfs cpulist notation, rejecting overflow, duplicates and truncation.
 */
static inline int parse_cpu_list(const char *text, uint32_t *ids, size_t capacity)
{
	size_t count = 0;

	while (isspace((unsigned char)*text))
		text++;
	for (;;) {
		unsigned long long first, last;
		char *end;

		if (*text < '0' || *text > '9')
			return -1;
		errno = 0;
		first = strtoull(text, &end, 10);
		if (errno || first > UINT32_MAX)
			return -1;
		text = end;
		last = first;
		if (*text == '-') {
			text++;
			if (*text < '0' || *text > '9')
				return -1;
			errno = 0;
			last = strtoull(text, &end, 10);
			if (errno || last > UINT32_MAX || last < first)
				return -1;
			text = end;
		}
		if ((count && first <= ids[count - 1]) || last - first + 1 > capacity - count)
			return -1;
		for (unsigned long long cpu = first; cpu <= last; cpu++)
			ids[count++] = (uint32_t)cpu;
		if (*text != ',')
			break;
		text++;
	}
	while (isspace((unsigned char)*text))
		text++;
	return *text || count > INT32_MAX ? -1 : (int)count;
}
#endif
