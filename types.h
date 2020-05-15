typedef unsigned int   uint;
typedef unsigned short ushort;
typedef unsigned char  uchar;
typedef uint pde_t;
#define NULL ((void *)0)

//***2.1.4***
//Define a new struct for sigaction
struct sigaction
{
  void (*sa_handler)(int);
  uint sigmask;
  
};