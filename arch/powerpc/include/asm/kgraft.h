/*
 * kgraft.h - powerpc-specific Kernel Live Patching Core
 *
 * Copyright (C) 2015-2016, SUSE, IBM Corp.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */
#ifndef _ASM_POWERPC_KGRAFT_H
#define _ASM_POWERPC_KGRAFT_H

#include <linux/module.h>
#include <linux/ftrace.h>

#ifdef CONFIG_KGRAFT

static inline void kgr_set_regs_ip(struct pt_regs *regs, unsigned long ip)
{
	regs->nip = ip;
}

#define kgr_get_ftrace_location kgr_get_ftrace_location
static inline unsigned long kgr_get_ftrace_location(unsigned long faddr)
{
	/*
	 * Live patch works only with -mprofile-kernel on PPC. In this case,
	 * the ftrace location is always within the first 16 bytes.
	 */
	return ftrace_location_range(faddr, faddr + 16);
}
#endif /* CONFIG_KGRAFT */

#endif /* _ASM_POWERPC_KGRAFT_H */
