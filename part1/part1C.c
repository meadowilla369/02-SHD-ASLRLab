/*
 * Address Space Layout Randomization
 * Part 1C: Speculative Probing
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>
#include "lab.h"

static bool is_candidate_page(uint64_t addr) {
    errno = 0;

    int rc = access((const char *)addr, F_OK);

    if (rc == 0) {
        return true;
    }

    if (rc == -1 && errno != EFAULT) {
        return true;
    }

    return false;
}

/*
 * Part 1
 * Find and return the single mapped address within the range [low_bound, upper_bound).
 */
uint64_t find_address(uint64_t low_bound, uint64_t high_bound) {
    for (uint64_t addr = low_bound; addr < high_bound; addr += PAGE_SIZE) {
        if (is_candidate_page(addr)) {
            return addr;
        }
    }

    return 0;
}
