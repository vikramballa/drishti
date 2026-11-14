/*
 * Benign Windows test program, cross-compiled with clang + lld-link (no
 * Windows SDK or CRT needed; see build-pe.sh). It is only analysed by the
 * tests, never executed. Contains: imports from three DLLs, a dense switch
 * (jump table), a no-return wrapper around ExitProcess, a stack buffer
 * (/GS cookie) and a minimal load-config directory.
 */
typedef unsigned long DWORD;
typedef unsigned short WORD;
typedef unsigned __int64 U64;
typedef __SIZE_TYPE__ size_t;
typedef __UINTPTR_TYPE__ UPTR;
typedef void *HANDLE;

#define IMPORT __declspec(dllimport)
#define API __stdcall
IMPORT void API ExitProcess(unsigned code);
IMPORT HANDLE API GetModuleHandleA(const char *name);
IMPORT void *API GetProcAddress(HANDLE mod, const char *name);
IMPORT int API VirtualProtect(void *addr, size_t n, DWORD prot, DWORD *old);
IMPORT int API IsDebuggerPresent(void);
IMPORT int API MessageBoxA(HANDLE w, const char *text, const char *cap, unsigned type);
IMPORT long API RegOpenKeyExA(HANDLE key, const char *sub, DWORD opt, DWORD sam, HANDLE *out);
IMPORT long API RegSetValueExA(HANDLE key, const char *name, DWORD r, DWORD type,
                               const unsigned char *data, DWORD n);

/* --- /GS support normally provided by the CRT --------------------------- */
UPTR __security_cookie = (UPTR)0x2B992DDFA232ull;
__declspec(noinline) void __fastcall __security_check_cookie(UPTR c) {
  if (c != __security_cookie)
    ExitProcess(0xC0000409u);
}
#if defined(__x86_64__) || defined(__aarch64__)
void __security_init_cookie(void) {}
#endif

/* --- Load configuration directory (IMAGE_LOAD_CONFIG_DIRECTORY) ----------
 * Written in assembly so the 32-bit GuardFlags field can hold the address of
 * the linker-synthesised absolute symbol __guard_flags (as the MSVC CRT does).
 * Field offsets: SecurityCookie 0x58 / 0x3c, GuardCFFunctionTable 0x80 / 0x50,
 * GuardCFFunctionCount 0x88 / 0x54, GuardFlags 0x90 / 0x58 (PE32+ / PE32). */
#if defined(__i386__)
__asm__(".section .rdata,\"dr\"\n"
        ".globl __load_config_used\n"
        ".p2align 2\n"
        "__load_config_used:\n"
        ".long 0x80\n"
        ".zero 56\n"
        ".long ___security_cookie\n"
        ".zero 16\n"
        ".long ___guard_fids_table\n"
        ".long ___guard_fids_count\n"
        ".long ___guard_flags\n"
        ".zero 36\n"
        ".text\n");
#else
__asm__(".section .rdata,\"dr\"\n"
        ".globl _load_config_used\n"
        ".p2align 3\n"
        "_load_config_used:\n"
        ".long 0x100\n"
        ".zero 84\n"
        ".quad __security_cookie\n"
        ".zero 32\n"
        ".quad __guard_fids_table\n"
        ".quad __guard_fids_count\n"
        ".long __guard_flags\n"
        ".zero 108\n"
        ".text\n");
#endif

/* --- Program ------------------------------------------------------------- */
static const char RUN_KEY[] = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
static const char HOME[] = "https://www.example.net/pe-sample";

__declspec(noinline) static void die(unsigned code) {
  MessageBoxA(0, "fatal error", "sample", 0x10);
  ExitProcess(code);
}

__declspec(noinline) int classify(int x, int y) {
  switch (x) {
  case 0: return y + 17;
  case 1: return y * 29;
  case 2: return y - 31;
  case 3: return y ^ 43;
  case 4: return y << 3;
  case 5: return y / 7;
  case 6: return y % 9;
  case 7: return y | 89;
  case 8: return y & 97;
  case 9: return -y;
  default: return -1;
  }
}

__declspec(noinline) static int copy_name(char *dst, const char *src) {
  char tmp[64];
  int i = 0;
  for (; src[i] && i < 63; i++)
    tmp[i] = src[i] ^ 0x20;
  tmp[i] = 0;
  for (int k = 0; k <= i; k++)
    dst[k] = tmp[k];
  return i;
}

__declspec(noinline) static int persist(void) {
  HANDLE key = 0;
  if (RegOpenKeyExA((HANDLE)(UPTR)0x80000001u, RUN_KEY, 0, 0x20006, &key) != 0)
    return -1;
  return (int)RegSetValueExA(key, "sample", 0, 1, (const unsigned char *)HOME, sizeof HOME);
}

void mainCRTStartup(void) {
  char name[64];
  if (IsDebuggerPresent())
    die(2);
  HANDLE k32 = GetModuleHandleA("kernel32.dll");
  void *p = GetProcAddress(k32, "Sleep");
  DWORD old = 0;
  VirtualProtect(p, 16, 0x40, &old);
  int n = copy_name(name, HOME);
  ExitProcess((unsigned)(classify(n & 15, n) + persist()));
}
