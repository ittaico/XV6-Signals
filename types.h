typedef unsigned int   uint;
typedef unsigned short ushort;
typedef unsigned char  uchar;
typedef uint pde_t;
#define NULL ((void *)0)

//ittai

struct sigaction
{
  void (*sa_handler)(int);
  uint sigmask;
  
};