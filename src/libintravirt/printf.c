/* Copyright (C) 2014 Stony Brook University
   This file is part of Graphene Library OS.

   Graphene Library OS is free software: you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public License
   as published by the Free Software Foundation, either version 3 of the
   License, or (at your option) any later version.

   Graphene Library OS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include <shim_passthru.h>
#include <api.h>
#include <shim_trampoline.h>
#include <rawcall.h>

int quiet = 1;

// Collect up to PRINTBUF_SIZE characters into a buffer
// and perform ONE system call to print all of them,
// in order to make the lines output to the console atomic
// and prevent interrupts from causing context switches
// in the middle of a console output line and such.

#define PRINTBUF_SIZE        256

struct printbuf {
    int idx;    // current buffer index
    int cnt;    // total bytes printed so far
    char buf[PRINTBUF_SIZE];
};

int fputch(void* f, int ch, void* _b) {
    __UNUSED(f);
    struct printbuf *b = _b;
    b->buf[b->idx++] = ch;
    if (b->idx == PRINTBUF_SIZE - 1) {
        rawcall(write, 1, b->buf, b->idx);
        b->idx = 0;
    }
    b->cnt++;
    return 0;
}

int vprintf(const char* fmt, va_list ap) {
    struct printbuf b;
    b.idx = 0;
    b.cnt = 0;
    vfprintfmt_fputch(NULL, &b, fmt, ap);
    rawcall(write, 1, b.buf, b.idx);
    return b.cnt;
}

int printf(const char* fmt, ...) {
    if (quiet == 1)
        return 0;
    va_list ap;
    int cnt;
    va_start(ap, fmt);
    cnt = vprintf(fmt, ap);
    va_end(ap);
    return cnt;
}
