/* Qualification fixture only: real sd_notify and owned Unix listeners, no RPCs. */
#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stopped;
static const char *root, *role;

static void event(const char *name) {
    char path[512];
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    snprintf(path, sizeof(path), "%s/events.txt", root);
    FILE *f = fopen(path, "a");
    if (!f) exit(20);
    fprintf(f, "%ld.%09ld %s %s %ld\n", now.tv_sec, now.tv_nsec, role, name, (long)getpid());
    if (fclose(f)) exit(21);
}

static void notify(void) {
    const char *path = getenv("NOTIFY_SOCKET");
    if (!path || strlen(path) >= sizeof(((struct sockaddr_un *)0)->sun_path)) exit(22);
    int fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) exit(23);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    strcpy(address.sun_path, path);
    if (path[0] == '@') address.sun_path[0] = 0;
    socklen_t length = offsetof(struct sockaddr_un, sun_path) + strlen(path) + (path[0] != '@');
    if (sendto(fd, "READY=1\nWATCHDOG=1", 18, 0, (struct sockaddr *)&address, length) < 0) exit(24);
    close(fd);
    event("notify");
}

static void listener(const char *name) {
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    if (snprintf(address.sun_path, sizeof(address.sun_path), "%s/run/sysbox/%s", root, name)
        >= (int)sizeof(address.sun_path)) exit(25);
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0 || bind(fd, (struct sockaddr *)&address, sizeof(address))
        || chmod(address.sun_path, 0600) || listen(fd, 8)) exit(26);
    /* Keep the fd open in this MainPID. Probes inspect it without creating RPCs. */
}

static void on_signal(int signal) { (void)signal; stopped = 1; }

int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "--version")) {
        puts("qualification mock; not a Sysbox binary");
        return 0;
    }
    root = getenv("SBQ_ROOT");
    role = getenv("SBQ_ROLE");
    if (!root || !role || strncmp(root, "/run/umbra-sbq-", 15)) return 27;
    signal(SIGTERM, on_signal);
    signal(SIGINT, on_signal);
    umask(077);
    event("start");
    if (!strcmp(role, "app")) { event("complete"); return 0; }
    int skip = getenv("SBQ_NO_NOTIFY") != NULL;
    if (!skip && strcmp(role, "sysbox")) notify();
    unsigned delay = getenv("SBQ_SOCKET_DELAY_MS") ? (unsigned)atoi(getenv("SBQ_SOCKET_DELAY_MS")) : 150;
    usleep(delay * 1000);
    if (getenv("SBQ_EXIT_BEFORE_SOCKET")) { event("die"); return 42; }
    if (getenv("SBQ_OTHER_LISTENER_PID")) {
        pid_t child = fork();
        if (child < 0) return 28;
        if (child > 0) {
            while (!stopped) pause();
            return 0;
        }
    }
    if (!strcmp(role, "mgr")) listener("sysmgr.sock");
    if (!strcmp(role, "fs")) {
        listener("sysfs.sock");
        listener("sysfs-seccomp.sock");
    }
    event("listeners");
    while (!stopped) pause();
    event("stop");
    return 0;
}
