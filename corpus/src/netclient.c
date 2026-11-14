#include <netdb.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
/*
 * Benign "update checker" used as a test fixture: networking, process
 * spawning, a crypto constant table, indicator-like strings (documentation
 * domains / TEST-NET addresses only) and a chain of no-return wrappers.
 * Tests only compile and analyse it; it is never executed.
 */
extern char **environ;

static const uint32_t K256[16] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174};
static const char UPDATE_URL[] = "https://updates.example.com/api/v1/check";
static const char MIRROR_IP[] = "203.0.113.77";
static const char CONTACT[] = "support@example.com";
static const char CONFIG_PATH[] = "/etc/netclient.conf";

__attribute__((noinline)) static void fatal(const char *m) {
  fprintf(stderr, "netclient: %s\n", m);
  exit(3);
}
/* Wrapper chain: usage -> fatal -> exit. Only `exit` is known by name. */
__attribute__((noinline)) static void usage(const char *argv0) {
  fprintf(stderr, "usage: %s host [port]\n", argv0);
  fatal("bad arguments");
}
__attribute__((noinline)) static void must(int v, const char *what) {
  if (v < 0) {
    perror(what);
    fatal("aborting");
  }
}
__attribute__((noinline)) static uint32_t mix(const char *s, size_t n) {
  uint32_t h = 0x6a09e667;
  for (size_t i = 0; i < n; i++)
    h = (h << 5 | h >> 27) ^ (K256[i % 16] + (uint8_t)s[i]);
  return h;
}
__attribute__((noinline)) static int open_conn(const char *host, const char *port) {
  struct addrinfo hints, *res = NULL;
  memset(&hints, 0, sizeof hints);
  hints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo(host, port, &hints, &res) != 0)
    return -1;
  int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
  if (fd >= 0 && connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
    close(fd);
    fd = -1;
  }
  freeaddrinfo(res);
  return fd;
}
__attribute__((noinline)) static long send_all(int fd, const char *buf, size_t n) {
  size_t off = 0;
  while (off < n) {
    long k = send(fd, buf + off, n - off, 0);
    if (k <= 0)
      return -1;
    off += (size_t)k;
  }
  return (long)off;
}
__attribute__((noinline)) static int run_helper(const char *path) {
  pid_t pid;
  char *args[] = {(char *)path, "--version", NULL};
  if (posix_spawn(&pid, path, NULL, NULL, args, environ) != 0)
    return -1;
  int st = 0;
  waitpid(pid, &st, 0);
  return WIFEXITED(st) ? WEXITSTATUS(st) : -1;
}
__attribute__((noinline)) static int parse_port(const char *s) {
  int p = 0;
  for (; *s; s++) {
    if (*s < '0' || *s > '9')
      usage("netclient");
    p = p * 10 + (*s - '0');
  }
  return p > 0 && p < 65536 ? p : 443;
}
int main(int argc, char **argv) {
  if (argc < 2)
    usage(argv[0]);
  int port = argc > 2 ? parse_port(argv[2]) : 443;
  char req[256];
  int n = snprintf(req, sizeof req, "GET %s HTTP/1.1\r\nHost: %s:%d\r\nX-Contact: %s\r\n\r\n",
                   UPDATE_URL, argv[1], port, CONTACT);
  int fd = open_conn(argv[1], "443");
  if (fd < 0)
    fd = open_conn(MIRROR_IP, "443");
  must(fd, "connect");
  must((int)send_all(fd, req, (size_t)n), "send");
  printf("%08x %d %s\n", mix(req, (size_t)n), run_helper("/usr/bin/true"), CONFIG_PATH);
  close(fd);
  return 0;
}
