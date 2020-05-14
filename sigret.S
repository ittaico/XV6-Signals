#include "traps.h"
#include "syscall.h"

.global startsigret
.global endsigret

startsigret:
	movl $SYS_sigret, %eax
	int $T_SYSCALL
endsigret: