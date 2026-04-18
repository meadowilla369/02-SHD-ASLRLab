/*
 * Address Space Layout Randomization
 * Part 1A: Egghunter
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>

#include "lab.h"

static bool is_candidate_page(uint64_t addr) {
    errno = 0;

    /* Use the candidate page as the pathname pointer for access(). */
    int rc = access((const char *)addr, F_OK);

    /* nếu call thành công hoặc thất bại theo kiểu "addr hợp lệ" */
    /* thì coi như candidate */
    if (rc == 0) {
        return true;
    }

    if (rc == -1){
        /* nếu thất bại theo kiểu "addr không dùng được" */
        /* thì loại */
        if (errno == EFAULT) {
            return false;
        } else {
            return true;
        }
    }

    return false;
}

uint64_t find_address(uint64_t low_bound, uint64_t high_bound) {
    if (low_bound >= high_bound) {
        return 0;
    }

    for (uint64_t addr = low_bound; addr < high_bound; addr += PAGE_SIZE) {
        if (is_candidate_page(addr)) {
            return addr;
        }
    }

    return 0;
}
