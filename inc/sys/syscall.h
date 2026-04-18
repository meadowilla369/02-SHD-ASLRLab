#ifndef PORTABLE_SYS_SYSCALL_H
#define PORTABLE_SYS_SYSCALL_H

#include_next <sys/syscall.h>

#if !defined(SYS_access) && defined(SYS_faccessat)
#define SYS_access SYS_faccessat
#endif

#endif
