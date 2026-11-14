#include <stdio.h>
#include <stdlib.h>
#include <string.h>
/* Dense + sparse switches, loops, recursion, function pointers. */
int dense(int x) {
  switch (x) {
  case 0: return 11; case 1: return 23; case 2: return 37; case 3: return 41;
  case 4: return 53; case 5: return 67; case 6: return 71; case 7: return 89;
  case 8: return 97; default: return -1;
  }
}
int sparse(int x) {
  switch (x) { case 3: return 1; case 100: return 2; case 1000: return 3; case 77777: return 4; default: return 0; }
}
static int fib(int n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }
typedef int (*op)(int, int);
static int add(int a, int b) { return a + b; }
static int mul(int a, int b) { return a * b; }
static op ops[] = {add, mul};
struct conn { char host[32]; unsigned short port; int fd; };
static void init_conn(struct conn *c, const char *h, unsigned short p) {
  strncpy(c->host, h, sizeof c->host - 1); c->port = p; c->fd = -1;
}
static void decrypt(char *s, size_t n, char k) { for (size_t i = 0; i < n; i++) s[i] ^= k; }
static __attribute__((noinline)) void die(const char *m) { fprintf(stderr, "%s\n", m); exit(2); }
int state_machine(const char *s) {
  int st = 0;
  for (; *s; s++) {
    switch (st) {
    case 0: st = (*s == 'G') ? 1 : 0; break;
    case 1: st = (*s == 'E') ? 2 : 0; break;
    case 2: st = (*s == 'T') ? 3 : 0; break;
    case 3: return 1;
    }
  }
  return st == 3;
}
int main(int argc, char **argv) {
  struct conn c; init_conn(&c, "example.org", 8080);
  char secret[] = {'h' ^ 7, 'i' ^ 7, 0};
  decrypt(secret, 2, 7);
  if (argc > 5) die("too many args");
  printf("%d %d %d %d %s %d %s\n", dense(argc), sparse(argc * 100), fib(10), ops[argc & 1](3, 4), c.host, state_machine(argc > 1 ? argv[1] : "GET /"), secret);
  return 0;
}
