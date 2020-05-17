#include "traps.h"
#include "syscall.h"

.globl startsigret
.globl endsigret

startsigret:
	movl $SYS_sigret, %eax
	int $T_SYSCALL
endsigret: