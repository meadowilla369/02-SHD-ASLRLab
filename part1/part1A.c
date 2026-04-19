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

    /*
     * Probe "addr" by pretending it is a pathname for access().
     * If the pointer is unmapped, the kernel reports EFAULT.
     * Any other result means the page is mapped and the kernel could read it.
     */
    int rc = access((const char *)addr, F_OK);

    if (rc == 0) {
        return true;
    }

    if (rc == -1){
        /*
         * EFAULT means the address is not a valid userspace pointer.
         * Errors such as ENOENT still prove the page was mapped enough
         * for the kernel to dereference the pointer.
         */
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

    /*
     * The hidden page is page-aligned, so we only need one probe per page.
     * Return the first mapped page we find inside the search interval.
     */
    for (uint64_t addr = low_bound; addr < high_bound; addr += PAGE_SIZE) {
        if (is_candidate_page(addr)) {
            return addr;
        }
    }

    return 0;
}
