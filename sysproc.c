#include "types.h"
#include "x86.h"
#include "defs.h"
#include "date.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"

int
sys_fork(void)
{
  return fork();
}

int
sys_exit(void)
{
  exit();
  return 0;  // not reached
}

int
sys_wait(void)
{
  return wait();
}

int
sys_kill(void)
{
  int pid, signum;

  if(argint(0, &pid) < 0)         //Get the pid
    return -1;
  if(argint(1, &signum) < 0)      //***2.2.1*** get the signum
    return -1;
  return kill(pid,signum);        //Send the signum to the proc.c to hendller it.
}

int
sys_getpid(void)
{
  return myproc()->pid;
}

int
sys_sbrk(void)
{
  int addr;
  int n;

  if(argint(0, &n) < 0)
    return -1;
  addr = myproc()->sz;
  if(growproc(n) < 0)
    return -1;
  return addr;
}

int
sys_sleep(void)
{
  int n;
  uint ticks0;

  if(argint(0, &n) < 0)
    return -1;
  acquire(&tickslock);
  ticks0 = ticks;
  while(ticks - ticks0 < n){
    if(myproc()->killed){
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

// return how many clock tick interrupts have occurred
// since start.
int
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}

//***2.1.3***
//The system_call will update the process signal mask
//and return the old signal mask.
int
sys_sigprocmask(void)
{
  uint sigmask;

    if(argint(0,(int*) &sigmask) < 0)
    return -1;

    return sigprocmask(sigmask);

}

//***2.1.4***
//The system call will register a new handler for a given signal number. 
//The system call will get (int signum, const struct sigaction *act, struct sigaction *oldact)
//The system call will return 0 is success, -1 is returned.
int
sys_sigaction(void)
{
  int signum;
//  struct sigaction *act;
//  struct sigaction *oldact;
    char *act;
    char *oldact;

  if (argint(0,&signum)<0)
    return -1;
  if(argptr(1,&act,sizeof(act))<0)
    return -1;
  if(argptr(2,&oldact,sizeof(oldact))<0)
    return -1;

  return sigaction(signum,(struct sigaction *)act,(struct sigaction *)oldact);
}

//Task 2.1.5
//The system call will br called implicitly 
//when returning from user space after handling a singal
int
sys_sigret(void){
  sigret();
  return 0;
}
