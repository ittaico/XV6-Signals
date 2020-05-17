#include "param.h"
#include "types.h"
#include "stat.h"
#include "user.h"
#include "fs.h"
#include "fcntl.h"
#include "syscall.h"
#include "traps.h"
#include "memlayout.h"

int
main(int argc, char *argv[]){
	uint newmask = 1;

	printf(1,"the new mask is %d\n",newmask);
	printf(1,"the kill return %d\n",kill(2,17));
	return 0;
}