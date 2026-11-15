# Test fixtures

- `elf-x86_64-plt.bin` — a tiny dynamic x86-64 Linux PIE built on macOS
  (no Linux machine needed) from this source, so ELF PLT handling is tested
  on every OS:

  ```c
  int socket(int,int,int); int connect(int,const void*,unsigned);
  int getaddrinfo(const char*,const char*,const void*,void**);
  __attribute__((noinline)) int open_conn(const char*h){ void*r; getaddrinfo(h,"80",0,&r); int s=socket(2,1,0); connect(s,r,16); return s;}
  void _start(void){ open_conn("x"); for(;;); }
  ```

  `clang --target=x86_64-linux-gnu -O2 -fPIC -fno-asynchronous-unwind-tables -c t.c`,
  then `rust-lld -flavor gnu -pie --dynamic-linker /lib64/ld-linux-x86-64.so.2 -o elf-x86_64-plt.bin t.o libstub.so`
  (`libstub.so`: the three functions as empty stubs, linked with `-shared`).
  Not symbol-stripped: `open_conn` at 0x1380.
- `netclient-linux-x86_64-O2.bin` / `.stripped.bin` — `corpus/src/netclient.c`
  built by the Ubuntu CI runner exactly as the corpus tests build it
  (Ubuntu clang 21.1.8, GNU ld: `clang -g -O2`, then `strip`), downloaded
  from the `linux-samples` CI artifact. GNU ld writes an FDE covering the
  whole `.plt`, which once hid every PLT stub.
