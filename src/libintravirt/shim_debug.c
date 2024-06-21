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

/*
 * shim_debug.c
 *
 * This file contains codes for registering libraries to GDB.
 */

#include <api.h>
#include <shim_defs.h>
#include <shim_passthru.h>
#include <errno.h>
#include <elf.h>

#define ERIM_ISOLATE_UNTRUSTED
#define ERIM_SWAP_STACKS
#include <erim.h>

struct gdb_link_map {
    Elf64_Addr          l_addr;
    const char*         l_name;
    Elf64_Dyn*          l_ld;
    struct gdb_link_map* l_next;
    struct gdb_link_map* l_prev;
};

/* Rendezvous structure used by the run-time dynamic linker to communicate
   details of shared object loading to the debugger.  If the executable's
   dynamic section has a DT_DEBUG element, the run-time linker sets that
   element's value to the address where this structure can be found.  */
struct r_debug {
    int r_version; /* Version number for this protocol.  */

    struct gdb_link_map* r_map; /* Head of the chain of loaded objects.  */

    /* This is the address of a function internal to the run-time linker,
       that will always be called when the linker begins to map in a
       library or unmap it, and again when the mapping change is complete.
       The debugger can set a breakpoint at this address if it wants to
       notice shared object mapping changes.  */
    Elf64_Addr r_brk;
    enum gdb_r_state {
        /* This state value describes the mapping change taking place when
           the `r_brk' address is called.  */
        RT_CONSISTENT, /* Mapping change is complete.  */
        RT_ADD,        /* Beginning to add a new object.  */
        RT_DELETE      /* Beginning to remove an object mapping.  */
    } r_state;

    Elf64_Addr r_ldbase; /* Base address the linker is loaded at.  */
};

static struct gdb_link_map shim_map, exec_map, interp_map;

void _dl_debug_state(void);
asm(
  "nop\n\t"
  ".align 16\n\t"
  ".global _dl_debug_state\n\t"
  ".type _dl_debug_state,@function\n\t"
  "_dl_debug_state:\n\t"
  "endbr64\n\t"
  "retq\n\t"
);
struct r_debug _r_debug = {
    .r_version = 1,
    .r_map     = NULL,
    .r_brk     = (Elf64_Addr)&_dl_debug_state,
    .r_state   = RT_CONSISTENT,
    .r_ldbase  = 0,
};

void init_debugger(Elf64_Addr base, const char* loader_name, Elf64_Dyn* dyn,
                   Elf64_Addr exec_base, const char* exec_name, Elf64_Dyn* exec_dyn,
                   Elf64_Addr interp_base, const char* interp_name, Elf64_Dyn* interp_dyn) {
    /* Add shim */
    _r_debug.r_state = RT_ADD;
    _dl_debug_state();

    shim_map.l_addr = base;
    shim_map.l_name = loader_name;
    shim_map.l_ld   = dyn;

    _r_debug.r_map = &shim_map;
    _r_debug.r_ldbase = base;

    _r_debug.r_state = RT_CONSISTENT;
    _dl_debug_state();

    /* Add exec */
    _r_debug.r_state = RT_ADD;
    _dl_debug_state();

    exec_map.l_addr = exec_base;
    exec_map.l_name = exec_name;
    exec_map.l_ld   = exec_dyn;
    shim_map.l_next = &exec_map;
    exec_map.l_prev = &shim_map;

    _r_debug.r_state = RT_CONSISTENT;
    _dl_debug_state();

    /* Add interp (if exists) */
    if (interp_base) {
        _r_debug.r_state = RT_ADD;
        _dl_debug_state();

        interp_map.l_addr = interp_base;
        interp_map.l_name = interp_name;
        interp_map.l_ld   = interp_dyn;
        exec_map.l_next   = &interp_map;
        interp_map.l_prev = &exec_map;

        _r_debug.r_state = RT_CONSISTENT;
        _dl_debug_state();
    }
}


void _dl_debug_state(void);
asm(
  "nop\n\t"
  ".align 16\n\t"
  ".global gdb_trap\n\t"
  ".type gdb_trap,@function\n\t"
  "gdb_trap:\n\t"
  "endbr64\n\t"
  "call _gdb_trap\n\t"
  "retq\n\t"
);
void _gdb_trap(struct r_debug* target) {
    erim_switch_to_trusted;
    _r_debug.r_state = target->r_state;

    struct gdb_link_map* last = &shim_map;
    while (last->l_next)
        last = last->l_next;

    last->l_next = target->r_map;
    if (target->r_map)
        target->r_map->l_prev = last;

    _dl_debug_state();

    last->l_next = NULL;
    if (target->r_map)
        target->r_map->l_prev = NULL;
    erim_switch_to_untrusted;
}
