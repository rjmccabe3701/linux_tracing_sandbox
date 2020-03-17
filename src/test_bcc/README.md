# BCC playground
These are my notes from playing around with
[this](http://www.brendangregg.com/bpf-performance-tools-book.html) excellent BCC book.


## Tracing applications running in a docker container

Example:

```c
//Compile with
// gcc -O3 -fno-omit-frame-pointer tmp.c
#include <stdlib.h>
#include <unistd.h>

void __attribute__ ((noinline))  func()
{
   int* i = malloc(4);
   //Don't optimize this call away
   asm volatile("" : : "r,m"(i) : "memory");
   free(i);
}

int main(void)
{
   while(1)
   {
      func();
   }
}
```

If you run this inside a container, the ``-p <PID>`` doesn't seem to work.  Looks to be related to this:
https://github.com/iovisor/bcc/issues/1366
Looks like BCC doesn't enter the containers mount PID mount space, see:
https://github.com/iovisor/bcc/pull/2710

So one way around this is to do this if you want to trace from with inside your container:

```bash
#Tracing from within side container --> note: cannot use the target PID
/usr/share/bcc/tools/funccount /src/build/a.out:func
```

This is annoying because you have to have the bcc tools installed inside you container.  An alternative
is to trace the process from the host machine via the ``/proc/[pid]/root`` mount.  See:
https://github.com/iovisor/bcc/pull/2324

```bash
#Tracing the container process (pid 25844) running inside container
# Note, adding a "-p 25844" option doesn't seem to work
/usr/share/bcc/tools/funccount /proc/25844/root/src/build/a.out:func
```

## Tracing C++ code

Consider a C++ version of the program above:

```c++
#include <stdlib.h>
#include <unistd.h>

struct Foo
{
   void __attribute__ ((noinline))  func()
   {
      i = (int*)malloc(4);
      asm volatile("" : : "r,m"(i) : "memory");
      free(i);
   }
   int* i;
};


int main(void)
{
   Foo foo;
   while(1)
   {
      foo.func();
   }
}
```

Find the mangled symbol like so:

```bash
> objdump -t ./a.out  | grep func
00000000000006c0  w    F .text  0000000000000027              _ZN3Foo4funcEv
```
Then just trace with the mangled name:

```bash
> /usr/share/bcc/tools/funccount /proc/26349/root/src/build/a.out:_ZN3Foo4funcEv -d 1
Tracing 1 functions for "b'/proc/26349/root/src/build/a.out:_ZN3Foo4funcEv'"... Hit Ctrl-C to end.

FUNC                                    COUNT
b'_ZN3Foo4funcEv'                      451288
Detaching...
```

