#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "x86.h"
#include "proc.h"
#include "spinlock.h"

struct {
  struct spinlock lock;
  struct proc proc[NPROC];
} ptable;

static struct proc *initproc;

int nextpid = 1;
extern void forkret(void);
extern void trapret(void);

//***Task 2.4*** declarate the sigret_start and end function
extern void startsigret(void);
extern void endsigret(void);
//

static void wakeup1(void *chan);

void
pinit(void)
{
  initlock(&ptable.lock, "ptable");
}

// Must be called with interrupts disabled
int
cpuid() {
  return mycpu()-cpus;
}

// Must be called with interrupts disabled to avoid the caller being
// rescheduled between reading lapicid and running through the loop.
struct cpu*
mycpu(void)
{
  int apicid, i;
  
  if(readeflags()&FL_IF)
    panic("mycpu called with interrupts enabled\n");
  
  apicid = lapicid();
  // APIC IDs are not guaranteed to be contiguous. Maybe we should have
  // a reverse map, or reserve a register to store &cpus[i].
  for (i = 0; i < ncpu; ++i) {
    if (cpus[i].apicid == apicid)
      return &cpus[i];
  }
  panic("unknown apicid\n");
}

// Disable interrupts so that we are not rescheduled
// while reading proc from the cpu structure
struct proc*
myproc(void) {
  struct cpu *c;
  struct proc *p;
  pushcli();
  c = mycpu();
  p = c->proc;
  popcli();
  return p;
}
/*
Before attempting to acquire a lock, acquire calls pushcli to disable
interrupts. Release call popcli to allow them to be enable.(The underlying)
x86 instruction to disable interrupts is named cli). pushcli and popcli 
are more then just wrappers around  cli and sti: thay are counted, so that it 
takes two calls to popcli to undo two calls to pushcli: this way if code
 acquires two different locks, interrupts will not be reenable until both
 locks have been released.

*/


// Pushcli/popcli are like cli/sti except that they are matched:
// it takes two popcli to undo two pushcli.  Also, if interrupts
// are off, then pushcli, popcli leaves them off.
int 
allocpid(void) 
{
  int pid;
  pushcli(); // disable interrupts to avoid deadlock
  do{
    pid = nextpid;
  }while(!cas(&nextpid,pid,pid+1));
  popcli();
  return pid;
  //I think it's should be return pid+1 like the exmpele
}
  /*old allocpid
{
  int pid;
  acquire(&ptable.lock);
  pid = nextpid++;
  release(&ptable.lock);
  return pid;

}*/



//***Task 3.2***
/*
static struct proc*
allocproc(void)
{

  struct proc *p;
  char *sp;
  int i;

  pushcli();    // acquire the intterputs 
  do{
    for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
      if(p->state == UNUSED){
        goto found;
      }
    }
      popcli()  //relese the intterupt before return (not new pid found)
      return 0;
    found:
  }while(!(cas(&p->state, UNUSED, EMBRYO)));  // The 'cas' loop countine until the p->state is EMBRYO
  popcli();   //Relese the intrrupts after the loop is break
  
  p->pid = allocpid();

  // Allocate kernel stack.
  if((p->kstack = kalloc()) == 0){
    p->state = UNUSED;
    return 0;
  }
  sp = p->kstack + KSTACKSIZE;

  // Leave room for trap frame.
  sp -= sizeof *p->tf;
  p->tf = (struct trapframe*)sp;

  // Set up new context to start executing at forkret,
  // which returns to trapret.
  sp -= 4;
  *(uint*)sp = (uint)trapret;

  sp -= sizeof *p->context;
  p->context = (struct context*)sp;
  memset(p->context, 0, sizeof *p->context);
  p->context->eip = (uint)forkret;
   */
  ///***Task 2.1.2***
/*
  p->pend_sig = 0;      
  p->mask = 0;
  for (i = 0; i < 32; i++){
    p->handlers[i] = (void *) SIG_DFL;
    p->sig_masks[i] = 0;
  }

  return p;
}
*/

//PAGEBREAK: 32
// Look in the process table for an UNUSED proc.
// If found, change state to EMBRYO and initialize
// state required to run in the kernel.
// Otherwise return 0.

static struct proc*
allocproc(void)
{

  struct proc *p;
  char *sp;
  int i;

  acquire(&ptable.lock);

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if(p->state == UNUSED)
      goto found;

  release(&ptable.lock);
  return 0;

found:
  p->state = EMBRYO;
  
  release(&ptable.lock);

  p->pid = allocpid();

  // Allocate kernel stack.
  if((p->kstack = kalloc()) == 0){
    p->state = UNUSED;
    return 0;
  }
  sp = p->kstack + KSTACKSIZE;

  // Leave room for trap frame.
  sp -= sizeof *p->tf;
  p->tf = (struct trapframe*)sp;

  // Set up new context to start executing at forkret,
  // which returns to trapret.
  sp -= 4;
  *(uint*)sp = (uint)trapret;

  sp -= sizeof *p->context;
  p->context = (struct context*)sp;
  memset(p->context, 0, sizeof *p->context);
  p->context->eip = (uint)forkret;

  ///***Task 2.1.2***
  p->pend_sig = 0;      
  p->mask = 0;
  for (i = 0; i < 32; i++){
    p->handlers[i] = (void *) SIG_DFL;
    p->sig_masks[i] = 0;
  }

  return p;
}


//PAGEBREAK: 32
// Set up first user process.
void
userinit(void)
{
  struct proc *p;
  extern char _binary_initcode_start[], _binary_initcode_size[];

  p = allocproc();
  
  initproc = p;
  if((p->pgdir = setupkvm()) == 0)
    panic("userinit: out of memory?");
  inituvm(p->pgdir, _binary_initcode_start, (int)_binary_initcode_size);
  p->sz = PGSIZE;
  memset(p->tf, 0, sizeof(*p->tf));
  p->tf->cs = (SEG_UCODE << 3) | DPL_USER;
  p->tf->ds = (SEG_UDATA << 3) | DPL_USER;
  p->tf->es = p->tf->ds;
  p->tf->ss = p->tf->ds;
  p->tf->eflags = FL_IF;
  p->tf->esp = PGSIZE;
  p->tf->eip = 0;  // beginning of initcode.S

  safestrcpy(p->name, "initcode", sizeof(p->name));
  p->cwd = namei("/");

  // this assignment to p->state lets other cores
  // run this process. the acquire forces the above
  // writes to be visible, and the lock is also needed
  // because the assignment might not be atomic.
  acquire(&ptable.lock);

  p->state = RUNNABLE;

  release(&ptable.lock);
}

// Grow current process's memory by n bytes.
// Return 0 on success, -1 on failure.
int
growproc(int n)
{
  uint sz;
  struct proc *curproc = myproc();

  sz = curproc->sz;
  if(n > 0){
    if((sz = allocuvm(curproc->pgdir, sz, sz + n)) == 0)
      return -1;
  } else if(n < 0){
    if((sz = deallocuvm(curproc->pgdir, sz, sz + n)) == 0)
      return -1;
  }
  curproc->sz = sz;
  switchuvm(curproc);
  return 0;
}

// Create a new process copying p as the parent.
// Sets up stack to return as if from system call.
// Caller must set state of returned proc to RUNNABLE.
int
fork(void)
{
  int i, pid;
  struct proc *np;
  struct proc *curproc = myproc();

  // Allocate process.
  if((np = allocproc()) == 0){
    return -1;
  }

  // Copy process state from proc.
  if((np->pgdir = copyuvm(curproc->pgdir, curproc->sz)) == 0){
    kfree(np->kstack);
    np->kstack = 0;
    np->state = UNUSED;
    return -1;
  }
  np->sz = curproc->sz;
  np->parent = curproc;
  *np->tf = *curproc->tf;

  // Clear %eax so that fork returns 0 in the child.
  np->tf->eax = 0;

  for(i = 0; i < NOFILE; i++)
    if(curproc->ofile[i])
      np->ofile[i] = filedup(curproc->ofile[i]);
  np->cwd = idup(curproc->cwd);

  safestrcpy(np->name, curproc->name, sizeof(curproc->name));

  pid = np->pid;

  ///***Task 2.1.2***
  np->mask = curproc->mask;
  for (i = 0; i<32; i++){
    np->handlers[i] = curproc->handlers[i];
    np->sig_masks[i] = curproc->sig_masks[i];
  } 


  acquire(&ptable.lock);

  np->state = RUNNABLE;

  release(&ptable.lock);

  return pid;
}

// Exit the current process.  Does not return.
// An exited process remains in the zombie state
// until its parent calls wait() to find out it exited.
void
exit(void)
{
  struct proc *curproc = myproc();
  struct proc *p;
  int fd;

  if(curproc == initproc)
    panic("init exiting");

  // Close all open files.
  for(fd = 0; fd < NOFILE; fd++){
    if(curproc->ofile[fd]){
      fileclose(curproc->ofile[fd]);
      curproc->ofile[fd] = 0;
    }
  }

  begin_op();
  iput(curproc->cwd);
  end_op();
  curproc->cwd = 0;

  acquire(&ptable.lock);

  // Parent might be sleeping in wait().
  wakeup1(curproc->parent);

  // Pass abandoned children to init.
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->parent == curproc){
      p->parent = initproc;
      if(p->state == ZOMBIE)
        wakeup1(initproc);
    }
  }

  // Jump into the scheduler, never to return.
  curproc->state = ZOMBIE;
  sched();
  panic("zombie exit");
}

// Wait for a child process to exit and return its pid.
// Return -1 if this process has no children.
int
wait(void)
{
  struct proc *p;
  int havekids, pid;
  struct proc *curproc = myproc();
  
  acquire(&ptable.lock);
  for(;;){
    // Scan through table looking for exited children.
    havekids = 0;
    for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
      if(p->parent != curproc)
        continue;
      havekids = 1;
      if(p->state == ZOMBIE){
        // Found one.
        pid = p->pid;
        kfree(p->kstack);
        p->kstack = 0;
        freevm(p->pgdir);
        p->pid = 0;
        p->parent = 0;
        p->name[0] = 0;
        p->killed = 0;
        p->state = UNUSED;
        release(&ptable.lock);
        return pid;
      }
    }

    // No point waiting if we don't have any children.
    if(!havekids || curproc->killed){
      release(&ptable.lock);
      return -1;
    }

    // Wait for children to exit.  (See wakeup1 call in proc_exit.)
    sleep(curproc, &ptable.lock);  //DOC: wait-sleep
  }
}

//PAGEBREAK: 42
// Per-CPU process scheduler.
// Each CPU calls scheduler() after setting itself up.
// Scheduler never returns.  It loops, doing:
//  - choose a process to run
//  - swtch to start running that process
//  - eventually that process transfers control
//      via swtch back to the scheduler.
void
scheduler(void)
{
  struct proc *p;
  struct cpu *c = mycpu();
  c->proc = 0;
  
  for(;;){
    // Enable interrupts on this processor.
    sti();

    // Loop over process table looking for process to run.
    acquire(&ptable.lock);
    for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
      if(p->state != RUNNABLE)
        continue;

      // Switch to chosen process.  It is the process's job
      // to release ptable.lock and then reacquire it
      // before jumping back to us.
      c->proc = p;
      switchuvm(p);
      p->state = RUNNING;

      swtch(&(c->scheduler), p->context);
      switchkvm();

      // Process is done running for now.
      // It should have changed its p->state before coming back.
      c->proc = 0;
    }
    release(&ptable.lock);

  }
}

// Enter scheduler.  Must hold only ptable.lock
// and have changed proc->state. Saves and restores
// intena because intena is a property of this
// kernel thread, not this CPU. It should
// be proc->intena and proc->ncli, but that would
// break in the few places where a lock is held but
// there's no process.
void
sched(void)
{
  int intena;
  struct proc *p = myproc();

  if(!holding(&ptable.lock))
    panic("sched ptable.lock");
  if(mycpu()->ncli != 1)
    panic("sched locks");
  if(p->state == RUNNING)
    panic("sched running");
  if(readeflags()&FL_IF)
    panic("sched interruptible");
  intena = mycpu()->intena;
  swtch(&p->context, mycpu()->scheduler);
  mycpu()->intena = intena;
}

// Give up the CPU for one scheduling round.
void
yield(void)
{
  acquire(&ptable.lock);  //DOC: yieldlock
  myproc()->state = RUNNABLE;
  sched();
  release(&ptable.lock);
}

// A fork child's very first scheduling by scheduler()
// will swtch here.  "Return" to user space.
void
forkret(void)
{
  static int first = 1;
  // Still holding ptable.lock from scheduler.
  release(&ptable.lock);

  if (first) {
    // Some initialization functions must be run in the context
    // of a regular process (e.g., they call sleep), and thus cannot
    // be run from main().
    first = 0;
    iinit(ROOTDEV);
    initlog(ROOTDEV);
  }

  // Return to "caller", actually trapret (see allocproc).
}

// Atomically release lock and sleep on chan.
// Reacquires lock when awakened.
void
sleep(void *chan, struct spinlock *lk)
{
  struct proc *p = myproc();
  
  if(p == 0)
    panic("sleep");

  if(lk == 0)
    panic("sleep without lk");

  // Must acquire ptable.lock in order to
  // change p->state and then call sched.
  // Once we hold ptable.lock, we can be
  // guaranteed that we won't miss any wakeup
  // (wakeup runs with ptable.lock locked),
  // so it's okay to release lk.
  if(lk != &ptable.lock){  //DOC: sleeplock0
    acquire(&ptable.lock);  //DOC: sleeplock1
    release(lk);
  }
  // Go to sleep.
  p->chan = chan;
  p->state = SLEEPING;

  sched();

  // Tidy up.
  p->chan = 0;

  // Reacquire original lock.
  if(lk != &ptable.lock){  //DOC: sleeplock2
    release(&ptable.lock);
    acquire(lk);
  }
}

//PAGEBREAK!
// Wake up all processes sleeping on chan.
// The ptable lock must be held.
static void
wakeup1(void *chan)
{
  struct proc *p;

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if(p->state == SLEEPING && p->chan == chan)
      p->state = RUNNABLE;
}

// Wake up all processes sleeping on chan.
void
wakeup(void *chan)
{
  acquire(&ptable.lock);
  wakeup1(chan);
  release(&ptable.lock);
}

// Kill the process with the given pid.
// Process won't exit until it returns
// to user space (see trap in trap.c).

/*
kill fails:
-when there is no pid like the one provided.
-when signum doens't exist
-when trying to send a signal to a process that is not "RUNNABLE", "SLEEPING", "Embryo"
*/
int
kill(int pid, int signum)
{
struct proc *p;
//$$$
//cprintf("Get into kill with pid %d and signum %d\n",pid,signum);
acquire(&ptable.lock);
for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
  if(p->pid == pid){
    //$$$
   // cprintf("Found a process inside the kill the pid is %d\n",pid);
    if(p->state != ZOMBIE && p->state != UNUSED && p->killed != 1){
      if(signum >= 0 && signum <= 31){
        p->pend_sig = p->pend_sig | (1<<signum);
      }
      return 0;
    }
  }
}
return -1;


  /* Old Kill */
  /*
  struct proc *p;

  acquire(&ptable.lock);
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->pid == pid){
      p->killed = 1;
      // Wake process from sleep if necessary.
      if(p->state == SLEEPING)
        p->state = RUNNABLE;
      release(&ptable.lock);
      return 0;
    }
  }
  release(&ptable.lock);
  return -1;
  */
}

//PAGEBREAK: 36
// Print a process listing to console.  For debugging.
// Runs when user types ^P on console.
// No lock to avoid wedging a stuck machine further.
void
procdump(void)
{
  static char *states[] = {
  [UNUSED]    "unused",
  [EMBRYO]    "embryo",
  [SLEEPING]  "sleep ",
  [RUNNABLE]  "runble",
  [RUNNING]   "run   ",
  [ZOMBIE]    "zombie"
  };
  int i;
  struct proc *p;
  char *state;
  uint pc[10];

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->state == UNUSED)
      continue;
    if(p->state >= 0 && p->state < NELEM(states) && states[p->state])
      state = states[p->state];
    else
      state = "???";
    cprintf("%d %s %s", p->pid, state, p->name);
    if(p->state == SLEEPING){
      getcallerpcs((uint*)p->context->ebp+2, pc);
      for(i=0; i<10 && pc[i] != 0; i++)
        cprintf(" %p", pc[i]);
    }
    cprintf("\n");
  }
}

//***2.1.3***
uint 
sigprocmask(uint sigmask){
  uint old_mask;
  struct proc *curproc = myproc();
  //$$$
  //cprintf("the new mask is %d\n",sigmask);
  old_mask = curproc->mask;
  curproc->mask = sigmask; //updating the process signal mask
  return old_mask;

}

// TODO/
int 
sigaction(int signum,const struct sigaction *act,struct sigaction *oldact){
  struct proc *curproc = myproc();
  //chack for the validity, the signum should be between 0-31 and the act can't be NULL
  if(signum < 0 || signum > 31 || act == NULL || act->sigmask < 0 || oldact == NULL){
    return -1;
  }
  //Check if the new handler is one of the fowlling:SIG_IGN,SIGSTOP,SIGKILL,SIGCONT,SIG_DFL 
  //or a pointer to a user space signal handler
 // if(act->sa_handler == SIG_IGN || act->sa_handler == SIGSTOP || act->sa_handler == SIGKILL ||act->sa_handler == SIGCONT ||act->sa_handler == SIG_DFL)
  //Chack is the struct oldact isn't NULL, if not will get the current sigaction
    oldact->sa_handler = curproc->handlers[signum]; //need to check the defanition of the sa_handler on the struct
    oldact->sigmask = curproc->sig_masks[signum];   //Copy the sig_masks[signum] of the old handler the oldact
    curproc->handlers[signum] = act->sa_handler;
    curproc->sig_masks[signum] = act->sigmask;



  return 0;
}

//Return to the user space by restoring the trap frame backup we saved before running the user signal handler.
// ??? Do we need to set a flag to know when we are going to user mode ???
void
sigret(void){
  struct proc *curproc = myproc();

  //restore trap frame backup.
  memmove(curproc->tf,curproc->tf_backup,sizeof(struct trapframe));
  curproc->tf->esp += sizeof(struct trapframe);

  //restore mask backup
  curproc->mask = curproc->mask_backup;
}

void
signalChecker(void){
  struct proc *p = myproc();
  int pendingSignalCheckerBit,maskCheckerBit,i ;
 // struct sigaction* currentSigaction; //*** we dont use the sigaction
  struct trapframe* tp;
  if(!p){  //process is not NULL
    return;
  }
  /*
  checking for the process's 32 possible pending signals and handaling them.
  signal numbers are located in proc.h
  ??? Do we need to acquire the ptable ???
  */
  for (i = 0; i < 32; i++){
    pendingSignalCheckerBit = p->pend_sig & (1<<i); //Check if the bit in position i of pend_sig is 1
    //Q: when do we need to set the mask from the sig_masks.
    maskCheckerBit = p->mask & (1<<i);   // Check if the bit in the i place at the mask is 1 

    if (pendingSignalCheckerBit && (!maskCheckerBit ||  i == SIGKILL || i == SIGSTOP)){  //SIGSTOP and SIGKILL can not be blocked
      if(i == SIGKILL){ // SIGKILL Handling
        sigkillhandler:
        p->killed = 1;
        if(p->state == SLEEPING)
          p->state = RUNNABLE;
        continue;
      }

      // SIGSTOP Handling, loop until the process recieved the SIGCONT signal.
      if(i == SIGSTOP){
        sigstophandler:
        p->stopped = 1;
        while((p->pend_sig & (1<<SIGCONT)) == 0){
          yield();
        }
        continue;
      }

      if(i == SIGCONT){
        sigconthandler:
        if(p->stopped == 1)
          p->stopped = 0;
        continue;
      }

      if(p->handlers[i] == (void*) SIG_IGN){//The handler of the current signal is IGN so we need to IGN the current signal
        continue;
      }
      //We can merge all the next ifs to the prev ifs only change the condition of every if.
      // for our choice.
      //The handler of the current siganal is DFL or KILL so we need to kill the process
      if(p->handlers[i] == (void*) SIG_DFL || p->handlers[i] == (void*) SIGKILL){
        goto sigkillhandler;
      }
      if(p->handlers[i] == (void*) SIGSTOP){//The handler of the current signal is STOP so we need to STOP the signal 
        goto sigstophandler;
      }
      if(p->handlers[i] == (void*) SIGCONT){// THe handler of the current signal is CONT so we need to do cont process
        goto sigconthandler;
      }

      // Handeling user handlers
      p->mask_backup = p->mask;
      p->mask = p->sig_masks[i];
      tp = p->tf;     // passing a pointer to the process trapframe
      tp->esp -= sizeof(struct trapframe); //Save space to the trapframe
      memmove((void*) (tp->esp), tp, sizeof(struct trapframe)); 
      p->tf_backup = (void*) (tp->esp); // ??? why void%

      //COPY FROM HAVIA active the signl handler in the user space with "injection" return to sigret function after finishing

      tp->esp -= &endsigret - &startsigret; //Save a space at the stack to the sigret function
      memmove((void*)tp->esp,startsigret,&endsigret - &startsigret); //By use the memmove function we can move the esp to the strat of the sigret function
      tp->esp -= 4; // Save place to the argument (signum)
      *((int *)(tp->esp)) = i; // pusing the argument (signum) to the steack
      tp->esp -= 4; // Save place to the reteun address
      *((int *)(tp->eip)) = (int)p->handlers[i]; // move the eip to handler[i] function to run the handler
      return; // way return ? we dont need to countine the next signal to check ?    
    } 
  }
}