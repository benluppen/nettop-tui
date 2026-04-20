#define _GNU_SOURCE
#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#define MAX_CONNECTIONS 16384
#define MAX_SOCKETS 32768
#define MAX_DEVICES 1024
#define STR 256

typedef struct {
    unsigned long inode;
    int pid;
    char name[64];
    char command[STR];
    char user[64];
} SocketOwner;

typedef struct {
    char proto[8];
    char local_ip[80];
    int local_port;
    char remote_ip[80];
    int remote_port;
    char state[24];
    unsigned long inode;
    int pid;
    char process[64];
    char command[STR];
    char user[64];
    int external;
} Connection;

typedef struct {
    char kind[24];
    char name[96];
    char detail[STR];
    char state[48];
} Device;

typedef struct {
    Connection connections[MAX_CONNECTIONS];
    int connection_count;
    Connection ports[MAX_CONNECTIONS];
    int port_count;
    Device devices[MAX_DEVICES];
    int device_count;
    int unreadable;
    time_t timestamp;
    char host[128];
} Snapshot;

typedef struct {
    int offset;
    int external_only;
    double interval;
    int running;
} AppState;

static struct termios saved_term;
static int term_saved = 0;

static const char *c_reset = "\033[0m";
static const char *c_bold = "\033[1m";
static const char *c_panel = "\033[38;5;45m";
static const char *c_magenta = "\033[38;5;171m";
static const char *c_green = "\033[38;5;82m";
static const char *c_yellow = "\033[38;5;214m";
static const char *c_red = "\033[38;5;196m";
static const char *c_gray = "\033[38;5;245m";
static const char *c_white = "\033[38;5;255m";
static const char *bg = "\033[48;5;235m";

static void copystr(char *dst, size_t n, const char *src) {
    if (!dst || n == 0) return;
    snprintf(dst, n, "%s", src ? src : "");
}

static void trim(char *s) {
    size_t n;
    if (!s) return;
    n = strlen(s);
    while (n && (s[n - 1] == '\n' || s[n - 1] == '\r' || isspace((unsigned char)s[n - 1]))) s[--n] = 0;
    while (*s && isspace((unsigned char)*s)) memmove(s, s + 1, strlen(s));
}

static int read_file(const char *path, char *buf, size_t n) {
    FILE *f;
    size_t r;
    if (!buf || n == 0) return 0;
    buf[0] = 0;
    f = fopen(path, "r");
    if (!f) return 0;
    r = fread(buf, 1, n - 1, f);
    buf[r] = 0;
    fclose(f);
    return (int)r;
}

static int is_digits(const char *s) {
    if (!s || !*s) return 0;
    while (*s) {
        if (!isdigit((unsigned char)*s)) return 0;
        s++;
    }
    return 1;
}

static const char *tcp_state(const char *hex) {
    if (!strcmp(hex, "01")) return "ESTABLISHED";
    if (!strcmp(hex, "02")) return "SYN_SENT";
    if (!strcmp(hex, "03")) return "SYN_RECV";
    if (!strcmp(hex, "04")) return "FIN_WAIT1";
    if (!strcmp(hex, "05")) return "FIN_WAIT2";
    if (!strcmp(hex, "06")) return "TIME_WAIT";
    if (!strcmp(hex, "07")) return "CLOSE";
    if (!strcmp(hex, "08")) return "CLOSE_WAIT";
    if (!strcmp(hex, "09")) return "LAST_ACK";
    if (!strcmp(hex, "0A")) return "LISTEN";
    if (!strcmp(hex, "0B")) return "CLOSING";
    if (!strcmp(hex, "0C")) return "NEW_SYN_RECV";
    return hex;
}

static void uid_name(uid_t uid, char *out, size_t n) {
    struct passwd *pw = getpwuid(uid);
    if (pw) snprintf(out, n, "%s", pw->pw_name);
    else snprintf(out, n, "%u", (unsigned int)uid);
}

static void process_info(int pid, char *name, size_t nn, char *cmd, size_t cn, char *user, size_t un) {
    char p[128], raw[STR];
    struct stat st;
    snprintf(p, sizeof(p), "/proc/%d/comm", pid);
    if (!read_file(p, name, nn)) snprintf(name, nn, "pid-%d", pid);
    trim(name);
    snprintf(p, sizeof(p), "/proc/%d/cmdline", pid);
    if (read_file(p, raw, sizeof(raw))) {
        size_t i, len = strlen(raw);
        for (i = 0; i < len; i++) if (raw[i] == 0) raw[i] = ' ';
        trim(raw);
        copystr(cmd, cn, raw[0] ? raw : name);
    } else copystr(cmd, cn, name);
    snprintf(p, sizeof(p), "/proc/%d", pid);
    if (!stat(p, &st)) uid_name(st.st_uid, user, un);
    else copystr(user, un, "?");
}

static void add_owner(SocketOwner *owners, int *count, unsigned long inode, int pid, const char *name, const char *cmd, const char *user) {
    int i;
    for (i = 0; i < *count; i++) {
        if (owners[i].inode == inode && owners[i].pid == pid) return;
    }
    if (*count >= MAX_SOCKETS) return;
    owners[*count].inode = inode;
    owners[*count].pid = pid;
    copystr(owners[*count].name, sizeof(owners[*count].name), name);
    copystr(owners[*count].command, sizeof(owners[*count].command), cmd);
    copystr(owners[*count].user, sizeof(owners[*count].user), user);
    *count += 1;
}

static int collect_owners(SocketOwner *owners, int *unreadable) {
    DIR *proc = opendir("/proc");
    struct dirent *pe;
    int count = 0;
    *unreadable = 0;
    if (!proc) return 0;
    while ((pe = readdir(proc))) {
        DIR *fd;
        struct dirent *fe;
        int pid;
        char fdpath[128], linkpath[256], target[256], name[64], cmd[STR], user[64];
        if (!is_digits(pe->d_name)) continue;
        pid = atoi(pe->d_name);
        process_info(pid, name, sizeof(name), cmd, sizeof(cmd), user, sizeof(user));
        snprintf(fdpath, sizeof(fdpath), "/proc/%d/fd", pid);
        fd = opendir(fdpath);
        if (!fd) {
            if (errno == EACCES || errno == EPERM) *unreadable += 1;
            continue;
        }
        while ((fe = readdir(fd))) {
            ssize_t r;
            unsigned long inode;
            if (fe->d_name[0] == '.') continue;
            snprintf(linkpath, sizeof(linkpath), "%s/%s", fdpath, fe->d_name);
            r = readlink(linkpath, target, sizeof(target) - 1);
            if (r < 0) continue;
            target[r] = 0;
            if (sscanf(target, "socket:[%lu]", &inode) == 1) add_owner(owners, &count, inode, pid, name, cmd, user);
        }
        closedir(fd);
    }
    closedir(proc);
    return count;
}

static SocketOwner *find_owner(SocketOwner *owners, int owner_count, unsigned long inode) {
    int i;
    for (i = 0; i < owner_count; i++) if (owners[i].inode == inode) return &owners[i];
    return NULL;
}

static void ipv4_from_hex(const char *hex, char *out, size_t n) {
    unsigned int b[4] = {0, 0, 0, 0};
    sscanf(hex, "%2x%2x%2x%2x", &b[3], &b[2], &b[1], &b[0]);
    snprintf(out, n, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
}

static unsigned int hexbyte(const char *s) {
    unsigned int x = 0;
    sscanf(s, "%2x", &x);
    return x;
}

static void ipv6_from_hex(const char *hex, char *out, size_t n) {
    unsigned char raw[16], addr[16];
    int i;
    for (i = 0; i < 16; i++) raw[i] = (unsigned char)hexbyte(hex + i * 2);
    for (i = 0; i < 16; i += 4) {
        addr[i] = raw[i + 3];
        addr[i + 1] = raw[i + 2];
        addr[i + 2] = raw[i + 1];
        addr[i + 3] = raw[i];
    }
    inet_ntop(AF_INET6, addr, out, n);
}

static void decode_endpoint(const char *value, int v6, char *ip, size_t in, int *port) {
    char host[80], ph[16];
    unsigned int p = 0;
    host[0] = ph[0] = 0;
    sscanf(value, "%79[^:]:%15s", host, ph);
    sscanf(ph, "%x", &p);
    *port = (int)p;
    if (v6) ipv6_from_hex(host, ip, in);
    else ipv4_from_hex(host, ip, in);
}

static int external_ip(const char *ip, int port) {
    int a, b, c, d;
    if (!port || !strcmp(ip, "0.0.0.0") || !strcmp(ip, "::")) return 0;
    if (sscanf(ip, "%d.%d.%d.%d", &a, &b, &c, &d) == 4) {
        if (a == 0 || a == 10 || a == 127 || a >= 224) return 0;
        if (a == 169 && b == 254) return 0;
        if (a == 172 && b >= 16 && b <= 31) return 0;
        if (a == 192 && b == 168) return 0;
        return 1;
    }
    if (!strcmp(ip, "::1")) return 0;
    if (!strncasecmp(ip, "fe80", 4) || !strncasecmp(ip, "fc", 2) || !strncasecmp(ip, "fd", 2) || !strncasecmp(ip, "ff", 2)) return 0;
    return 1;
}

static void parse_net_file(Snapshot *s, const char *proto, const char *file, SocketOwner *owners, int owner_count) {
    FILE *f = fopen(file, "r");
    char line[1024];
    int v6 = strstr(proto, "6") != NULL;
    if (!f) return;
    fgets(line, sizeof(line), f);
    while (fgets(line, sizeof(line), f)) {
        char local[96], remote[96], st[16];
        unsigned long inode = 0;
        SocketOwner *owner;
        Connection *c;
        if (s->connection_count >= MAX_CONNECTIONS) break;
        if (sscanf(line, " %*d: %95s %95s %15s %*s %*s %*s %*s %*s %lu", local, remote, st, &inode) != 4) continue;
        c = &s->connections[s->connection_count++];
        memset(c, 0, sizeof(*c));
        copystr(c->proto, sizeof(c->proto), proto);
        decode_endpoint(local, v6, c->local_ip, sizeof(c->local_ip), &c->local_port);
        decode_endpoint(remote, v6, c->remote_ip, sizeof(c->remote_ip), &c->remote_port);
        copystr(c->state, sizeof(c->state), proto[0] == 't' ? tcp_state(st) : "OPEN");
        c->inode = inode;
        c->pid = -1;
        owner = find_owner(owners, owner_count, inode);
        if (owner) {
            c->pid = owner->pid;
            copystr(c->process, sizeof(c->process), owner->name);
            copystr(c->command, sizeof(c->command), owner->command);
            copystr(c->user, sizeof(c->user), owner->user);
        } else {
            copystr(c->process, sizeof(c->process), "unknown");
            copystr(c->user, sizeof(c->user), "?");
        }
        c->external = external_ip(c->remote_ip, c->remote_port);
    }
    fclose(f);
}

static int same_port(Connection *a, Connection *b) {
    return !strcmp(a->proto, b->proto) && !strcmp(a->local_ip, b->local_ip) && a->local_port == b->local_port && a->pid == b->pid && !strcmp(a->process, b->process);
}

static void build_ports(Snapshot *s) {
    int i, j, exists;
    s->port_count = 0;
    for (i = 0; i < s->connection_count; i++) {
        Connection *c = &s->connections[i];
        if (strcmp(c->state, "LISTEN") && !(c->proto[0] == 'u' && c->remote_port == 0)) continue;
        exists = 0;
        for (j = 0; j < s->port_count; j++) if (same_port(&s->ports[j], c)) exists = 1;
        if (!exists && s->port_count < MAX_CONNECTIONS) s->ports[s->port_count++] = *c;
    }
}

static void add_device(Snapshot *s, const char *kind, const char *name, const char *state, const char *detail) {
    Device *d;
    if (s->device_count >= MAX_DEVICES) return;
    d = &s->devices[s->device_count++];
    copystr(d->kind, sizeof(d->kind), kind);
    copystr(d->name, sizeof(d->name), name);
    copystr(d->state, sizeof(d->state), state);
    copystr(d->detail, sizeof(d->detail), detail);
}

static void path_join(char *out, size_t n, const char *a, const char *b) {
    snprintf(out, n, "%s/%s", a, b);
}

static void collect_usb(Snapshot *s) {
    DIR *d = opendir("/sys/bus/usb/devices");
    struct dirent *e;
    if (!d) return;
    while ((e = readdir(d))) {
        char base[256], p[320], vendor[64], product_id[64], maker[96], product[96], speed[64], bus[32], dev[32], name[128], detail[STR];
        if (e->d_name[0] == '.') continue;
        path_join(base, sizeof(base), "/sys/bus/usb/devices", e->d_name);
        path_join(p, sizeof(p), base, "idVendor"); read_file(p, vendor, sizeof(vendor)); trim(vendor);
        path_join(p, sizeof(p), base, "idProduct"); read_file(p, product_id, sizeof(product_id)); trim(product_id);
        if (!vendor[0] || !product_id[0]) continue;
        path_join(p, sizeof(p), base, "manufacturer"); read_file(p, maker, sizeof(maker)); trim(maker);
        path_join(p, sizeof(p), base, "product"); read_file(p, product, sizeof(product)); trim(product);
        path_join(p, sizeof(p), base, "speed"); read_file(p, speed, sizeof(speed)); trim(speed);
        path_join(p, sizeof(p), base, "busnum"); read_file(p, bus, sizeof(bus)); trim(bus);
        path_join(p, sizeof(p), base, "devnum"); read_file(p, dev, sizeof(dev)); trim(dev);
        snprintf(name, sizeof(name), "%s", product[0] ? product : maker[0] ? maker : "USB device");
        snprintf(detail, sizeof(detail), "%s %s:%s%s%s%s%s", maker, vendor, product_id, bus[0] ? " bus " : "", bus, dev[0] ? " dev " : "", dev);
        if (speed[0]) snprintf(detail + strlen(detail), sizeof(detail) - strlen(detail), " %sMbps", speed);
        trim(detail);
        add_device(s, "usb", name, "connected", detail);
    }
    closedir(d);
}

static void human_bytes(unsigned long long bytes, char *out, size_t n) {
    const char *units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double v = (double)bytes;
    int i = 0;
    while (v >= 1024.0 && i < 4) { v /= 1024.0; i++; }
    snprintf(out, n, "%.1f%s", v, units[i]);
}

static void collect_block(Snapshot *s) {
    DIR *d = opendir("/sys/block");
    struct dirent *e;
    if (!d) return;
    while ((e = readdir(d))) {
        char base[256], p[320], removable[16], vendor[64], model[96], size_s[64], human[64], detail[STR];
        unsigned long long sectors = 0;
        if (e->d_name[0] == '.') continue;
        path_join(base, sizeof(base), "/sys/block", e->d_name);
        path_join(p, sizeof(p), base, "removable"); read_file(p, removable, sizeof(removable)); trim(removable);
        if (strcmp(removable, "1")) continue;
        path_join(p, sizeof(p), base, "device/vendor"); read_file(p, vendor, sizeof(vendor)); trim(vendor);
        path_join(p, sizeof(p), base, "device/model"); read_file(p, model, sizeof(model)); trim(model);
        path_join(p, sizeof(p), base, "size"); read_file(p, size_s, sizeof(size_s)); trim(size_s);
        if (sscanf(size_s, "%llu", &sectors) == 1) human_bytes(sectors * 512ULL, human, sizeof(human)); else human[0] = 0;
        snprintf(detail, sizeof(detail), "%s %s %s", vendor, model, human);
        trim(detail);
        add_device(s, "storage", e->d_name, "removable", detail);
    }
    closedir(d);
}

static void collect_netdev(Snapshot *s) {
    DIR *d = opendir("/sys/class/net");
    struct dirent *e;
    if (!d) return;
    while ((e = readdir(d))) {
        char base[256], p[320], oper[64], mac[96], carrier[32], detail[STR];
        if (e->d_name[0] == '.' || !strcmp(e->d_name, "lo")) continue;
        path_join(base, sizeof(base), "/sys/class/net", e->d_name);
        path_join(p, sizeof(p), base, "operstate"); read_file(p, oper, sizeof(oper)); trim(oper); if (!oper[0]) copystr(oper, sizeof(oper), "unknown");
        path_join(p, sizeof(p), base, "address"); read_file(p, mac, sizeof(mac)); trim(mac);
        path_join(p, sizeof(p), base, "carrier"); read_file(p, carrier, sizeof(carrier)); trim(carrier);
        snprintf(detail, sizeof(detail), "%s%s%s", mac, carrier[0] ? " carrier=" : "", carrier);
        add_device(s, "network", e->d_name, oper, detail);
    }
    closedir(d);
}

static void collect_bluetooth(Snapshot *s) {
    DIR *d = opendir("/sys/class/bluetooth");
    struct dirent *e;
    if (!d) return;
    while ((e = readdir(d))) {
        char base[256], p[320], address[96], power[64];
        if (e->d_name[0] == '.') continue;
        path_join(base, sizeof(base), "/sys/class/bluetooth", e->d_name);
        path_join(p, sizeof(p), base, "address"); read_file(p, address, sizeof(address)); trim(address);
        path_join(p, sizeof(p), base, "power/control"); read_file(p, power, sizeof(power)); trim(power); if (!power[0]) copystr(power, sizeof(power), "present");
        add_device(s, "bluetooth", e->d_name, power, address);
    }
    closedir(d);
}

static void collect_snapshot(Snapshot *s) {
    SocketOwner *owners = calloc(MAX_SOCKETS, sizeof(SocketOwner));
    int owner_count;
    if (!owners) return;
    memset(s, 0, sizeof(*s));
    s->timestamp = time(NULL);
    gethostname(s->host, sizeof(s->host));
    owner_count = collect_owners(owners, &s->unreadable);
    parse_net_file(s, "tcp", "/proc/net/tcp", owners, owner_count);
    parse_net_file(s, "tcp6", "/proc/net/tcp6", owners, owner_count);
    parse_net_file(s, "udp", "/proc/net/udp", owners, owner_count);
    parse_net_file(s, "udp6", "/proc/net/udp6", owners, owner_count);
    build_ports(s);
    collect_usb(s);
    collect_block(s);
    collect_netdev(s);
    collect_bluetooth(s);
    free(owners);
}

static int term_size(int *rows, int *cols) {
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == -1 || ws.ws_col == 0) {
        *rows = 30;
        *cols = 120;
        return 0;
    }
    *rows = ws.ws_row;
    *cols = ws.ws_col;
    return 1;
}

static void move_to(int y, int x) { printf("\033[%d;%dH", y + 1, x + 1); }
static void clear_screen(void) { printf("\033[2J\033[H"); }

static void print_fit(const char *text, int width) {
    int i, len = (int)strlen(text);
    for (i = 0; i < width && i < len; i++) putchar(text[i]);
    for (; i < width; i++) putchar(' ');
}

static void put_text(int y, int x, int width, const char *color, const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    move_to(y, x);
    printf("%s", color ? color : "");
    print_fit(buf, width);
    printf("%s", c_reset);
}

static void draw_panel(int y, int x, int h, int w, const char *title) {
    int i;
    if (h < 3 || w < 4) return;
    move_to(y, x); printf("%s╭", c_panel); for (i = 0; i < w - 2; i++) printf("─"); printf("╮%s", c_reset);
    put_text(y, x + 2, w - 4, c_bold, " %s ", title);
    for (i = 1; i < h - 1; i++) {
        move_to(y + i, x); printf("%s│%s", c_panel, c_reset);
        move_to(y + i, x + 1); print_fit("", w - 2);
        move_to(y + i, x + w - 1); printf("%s│%s", c_panel, c_reset);
    }
    move_to(y + h - 1, x); printf("%s╰", c_panel); for (i = 0; i < w - 2; i++) printf("─"); printf("╯%s", c_reset);
}

static void endpoint(char *out, size_t n, const char *ip, int port) {
    if (port) snprintf(out, n, "%s:%d", ip, port);
    else snprintf(out, n, "%s", ip);
}

static void draw_connections(Snapshot *s, AppState *app, int y, int x, int h, int w) {
    int i, row = 1, visible_index = 0, total = 0;
    put_text(y, x, w, c_bold, "PROTO STATE         LOCAL                  REMOTE                 PID    APP");
    for (i = 0; i < s->connection_count; i++) if (!app->external_only || s->connections[i].external) total++;
    if (app->offset > total - h + 1) app->offset = total - h + 1;
    if (app->offset < 0) app->offset = 0;
    for (i = 0; i < s->connection_count && row < h; i++) {
        Connection *c = &s->connections[i];
        char local[96], remote[96], line[512], pid[32];
        const char *col;
        if (app->external_only && !c->external) continue;
        if (visible_index++ < app->offset) continue;
        endpoint(local, sizeof(local), c->local_ip, c->local_port);
        endpoint(remote, sizeof(remote), c->remote_ip, c->remote_port);
        snprintf(pid, sizeof(pid), "%s", c->pid >= 0 ? "" : "-");
        if (c->pid >= 0) snprintf(pid, sizeof(pid), "%d", c->pid);
        snprintf(line, sizeof(line), "%-5s %-13s %-22.22s %-22.22s %-6s %s", c->proto, c->state, local, remote, pid, c->process);
        col = c->external ? c_magenta : !strcmp(c->state, "ESTABLISHED") ? c_green : (!strcmp(c->state, "LISTEN") || !strcmp(c->state, "OPEN")) ? c_yellow : c_gray;
        put_text(y + row, x, w, col, "%s", line);
        row++;
    }
}

static void draw_ports(Snapshot *s, int y, int x, int h, int w) {
    int i, row = 1;
    put_text(y, x, w, c_bold, "PORT  PROTO BIND                  APP");
    for (i = 0; i < s->port_count && row < h; i++) {
        char bind[96], app[128];
        endpoint(bind, sizeof(bind), s->ports[i].local_ip, s->ports[i].local_port);
        if (s->ports[i].pid >= 0) snprintf(app, sizeof(app), "%s (%d)", s->ports[i].process, s->ports[i].pid);
        else snprintf(app, sizeof(app), "%s", s->ports[i].process);
        put_text(y + row, x, w, !strcmp(s->ports[i].state, "LISTEN") ? c_yellow : c_green, "%-5d %-5s %-21.21s %s", s->ports[i].local_port, s->ports[i].proto, bind, app);
        row++;
    }
}

static void draw_devices(Snapshot *s, int y, int x, int h, int w) {
    int i, row = 1;
    put_text(y, x, w, c_bold, "TYPE       NAME                 STATE       DETAIL");
    if (!s->device_count) {
        put_text(y + 1, x, w, c_gray, "No USB/storage/network/bluetooth devices found");
        return;
    }
    for (i = 0; i < s->device_count && row < h; i++) {
        const char *col = (!strcmp(s->devices[i].state, "up") || !strcmp(s->devices[i].state, "connected") || !strcmp(s->devices[i].state, "removable")) ? c_green : c_gray;
        put_text(y + row, x, w, col, "%-10s %-20.20s %-11.11s %s", s->devices[i].kind, s->devices[i].name, s->devices[i].state, s->devices[i].detail);
        row++;
    }
}

static void draw(Snapshot *s, AppState *app) {
    static int last_rows = 0;
    static int last_cols = 0;
    int rows, cols, left_w, right_w, body_h, right_top, external = 0, apps = 0, i;
    int seen[4096], seen_count = 0;
    char stamp[64], note[256];
    struct tm *tmv = localtime(&s->timestamp);
    term_size(&rows, &cols);
    if (rows != last_rows || cols != last_cols) {
        clear_screen();
        last_rows = rows;
        last_cols = cols;
    } else {
        move_to(0, 0);
    }
    if (rows < 24 || cols < 90) {
        put_text(0, 0, cols, c_red, "nettop needs at least 90x24 terminal space");
        fflush(stdout);
        return;
    }
    for (i = 0; i < s->connection_count; i++) {
        int j, found = 0;
        if (s->connections[i].external) external++;
        if (s->connections[i].pid >= 0) {
            for (j = 0; j < seen_count; j++) if (seen[j] == s->connections[i].pid) found = 1;
            if (!found && seen_count < 4096) seen[seen_count++] = s->connections[i].pid;
        }
    }
    apps = seen_count;
    strftime(stamp, sizeof(stamp), "%H:%M:%S", tmv);
    printf("%s%s", bg, c_white);
    put_text(0, 0, cols, "", " NETTOP  %s  %d sockets  %d open ports  %d external  %d apps  %d devices%*s", s->host, s->connection_count, s->port_count, external, apps, s->device_count, 20, stamp);
    printf("%s", c_reset);
    if (s->unreadable) snprintf(note, sizeof(note), "some process owners hidden; run with sudo for full PID/app mapping (%d unreadable)", s->unreadable);
    else snprintf(note, sizeof(note), "live Linux socket/process/device monitor");
    put_text(1, 1, cols - 2, s->unreadable ? c_yellow : c_gray, "%s", note);
    body_h = rows - 4;
    left_w = cols * 62 / 100;
    if (left_w < 54) left_w = 54;
    right_w = cols - left_w - 1;
    right_top = body_h / 2;
    if (right_top < 8) right_top = 8;
    draw_panel(2, 0, body_h, left_w, "CONNECTIONS");
    draw_panel(2, left_w + 1, right_top, right_w, "OPEN PORTS");
    draw_panel(2 + right_top, left_w + 1, body_h - right_top, right_w, "EXTERNAL DEVICES");
    draw_connections(s, app, 3, 1, body_h - 2, left_w - 2);
    draw_ports(s, 3, left_w + 2, right_top - 2, right_w - 2);
    draw_devices(s, 3 + right_top, left_w + 2, body_h - right_top - 2, right_w - 2);
    printf("%s%s", bg, c_white);
    put_text(rows - 1, 0, cols, "", " q quit  r refresh  e toggle external filter  ↑/↓ scroll  mode: %s", app->external_only ? "external only" : "all sockets");
    printf("%s", c_reset);
    fflush(stdout);
}

static void restore_terminal(void) {
    if (term_saved) tcsetattr(STDIN_FILENO, TCSANOW, &saved_term);
    printf("\033[?25h\033[0m\n");
    fflush(stdout);
}

static void raw_terminal(void) {
    struct termios t;
    if (tcgetattr(STDIN_FILENO, &saved_term) == 0) {
        term_saved = 1;
        t = saved_term;
        t.c_lflag &= (tcflag_t)~(ICANON | ECHO);
        t.c_cc[VMIN] = 0;
        t.c_cc[VTIME] = 0;
        tcsetattr(STDIN_FILENO, TCSANOW, &t);
        atexit(restore_terminal);
    }
    printf("\033[?25l");
    clear_screen();
}

static int key_read(void) {
    unsigned char c;
    if (read(STDIN_FILENO, &c, 1) != 1) return 0;
    if (c == 27) {
        unsigned char seq[2];
        if (read(STDIN_FILENO, &seq[0], 1) == 1 && read(STDIN_FILENO, &seq[1], 1) == 1 && seq[0] == '[') {
            if (seq[1] == 'A') return 1001;
            if (seq[1] == 'B') return 1002;
            if (seq[1] == '5') { read(STDIN_FILENO, &seq[0], 1); return 1003; }
            if (seq[1] == '6') { read(STDIN_FILENO, &seq[0], 1); return 1004; }
        }
        return 27;
    }
    return c;
}

static void tui(double interval) {
    Snapshot *s = calloc(1, sizeof(Snapshot));
    AppState app;
    double elapsed = interval;
    if (!s) return;
    app.offset = 0;
    app.external_only = 0;
    app.interval = interval;
    app.running = 1;
    raw_terminal();
    while (app.running) {
        fd_set set;
        struct timeval tv;
        int ready, key;
        if (elapsed >= interval) {
            collect_snapshot(s);
            draw(s, &app);
            elapsed = 0.0;
        }
        FD_ZERO(&set);
        FD_SET(STDIN_FILENO, &set);
        tv.tv_sec = 0;
        tv.tv_usec = 100000;
        ready = select(STDIN_FILENO + 1, &set, NULL, NULL, &tv);
        elapsed += 0.1;
        if (ready <= 0) continue;
        key = key_read();
        if (key == 'q' || key == 'Q' || key == 27 || key == 3) app.running = 0;
        else if (key == 'r' || key == 'R') elapsed = interval;
        else if (key == 'e' || key == 'E') { app.external_only = !app.external_only; app.offset = 0; draw(s, &app); }
        else if (key == 1002) { app.offset++; draw(s, &app); }
        else if (key == 1001) { if (app.offset > 0) app.offset--; draw(s, &app); }
        else if (key == 1004) { app.offset += 10; draw(s, &app); }
        else if (key == 1003) { app.offset -= 10; if (app.offset < 0) app.offset = 0; draw(s, &app); }
    }
    free(s);
}

static void print_text(Snapshot *s) {
    int i;
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&s->timestamp));
    printf("nettop snapshot %s\n", ts);
    printf("connections=%d open_ports=%d devices=%d unreadable_processes=%d\n\n", s->connection_count, s->port_count, s->device_count, s->unreadable);
    printf("Open ports:\n");
    for (i = 0; i < s->port_count && i < 80; i++) {
        char pid[32];
        if (s->ports[i].pid >= 0) snprintf(pid, sizeof(pid), "%d", s->ports[i].pid);
        else copystr(pid, sizeof(pid), "-");
        printf("  %-5s %s:%-5d %-6s pid=%s app=%s\n", s->ports[i].proto, s->ports[i].local_ip, s->ports[i].local_port, s->ports[i].state, pid, s->ports[i].process);
    }
    printf("\nActive external connections:\n");
    for (i = 0; i < s->connection_count && i < 80; i++) if (s->connections[i].external) {
        char pid[32];
        if (s->connections[i].pid >= 0) snprintf(pid, sizeof(pid), "%d", s->connections[i].pid);
        else copystr(pid, sizeof(pid), "-");
        printf("  %-5s %s:%d -> %s:%d %s pid=%s app=%s\n", s->connections[i].proto, s->connections[i].local_ip, s->connections[i].local_port, s->connections[i].remote_ip, s->connections[i].remote_port, s->connections[i].state, pid, s->connections[i].process);
    }
    printf("\nExternal devices:\n");
    for (i = 0; i < s->device_count && i < 80; i++) printf("  %-10s %-22s %-12s %s\n", s->devices[i].kind, s->devices[i].name, s->devices[i].state, s->devices[i].detail);
}

static void json_escape(const char *s) {
    while (*s) {
        if (*s == '"' || *s == '\\') printf("\\%c", *s);
        else if (*s == '\n') printf("\\n");
        else if ((unsigned char)*s < 32) printf(" ");
        else putchar(*s);
        s++;
    }
}

static void print_json(Snapshot *s) {
    int i;
    printf("{\n  \"timestamp\": %ld,\n  \"connections\": [\n", (long)s->timestamp);
    for (i = 0; i < s->connection_count; i++) {
        Connection *c = &s->connections[i];
        printf("    {\"proto\": \""); json_escape(c->proto); printf("\", \"localIp\": \""); json_escape(c->local_ip); printf("\", \"localPort\": %d, \"remoteIp\": \"", c->local_port); json_escape(c->remote_ip); printf("\", \"remotePort\": %d, \"state\": \"", c->remote_port); json_escape(c->state); printf("\", \"pid\": %d, \"process\": \"", c->pid); json_escape(c->process); printf("\", \"external\": %s}%s\n", c->external ? "true" : "false", i == s->connection_count - 1 ? "" : ",");
    }
    printf("  ],\n  \"listeningPorts\": [\n");
    for (i = 0; i < s->port_count; i++) {
        Connection *c = &s->ports[i];
        printf("    {\"proto\": \""); json_escape(c->proto); printf("\", \"localIp\": \""); json_escape(c->local_ip); printf("\", \"localPort\": %d, \"state\": \"", c->local_port); json_escape(c->state); printf("\", \"pid\": %d, \"process\": \"", c->pid); json_escape(c->process); printf("\"}%s\n", i == s->port_count - 1 ? "" : ",");
    }
    printf("  ],\n  \"devices\": [\n");
    for (i = 0; i < s->device_count; i++) {
        Device *d = &s->devices[i];
        printf("    {\"kind\": \""); json_escape(d->kind); printf("\", \"name\": \""); json_escape(d->name); printf("\", \"state\": \""); json_escape(d->state); printf("\", \"detail\": \""); json_escape(d->detail); printf("\"}%s\n", i == s->device_count - 1 ? "" : ",");
    }
    printf("  ],\n  \"unreadableProcesses\": %d\n}\n", s->unreadable);
}

static void usage(void) {
    printf("nettop - lightweight native Linux network and device TUI\n\n");
    printf("Usage:\n  nettop [--interval seconds]\n  nettop --once [--json]\n\n");
    printf("Keys:\n  q or Esc       quit\n  r             refresh now\n  e             toggle external-connection filter\n  Up/Down       scroll connections\n  PageUp/PageDn scroll faster\n");
}

int main(int argc, char **argv) {
    int once = 0, json = 0, i;
    double interval = 2.0;
    Snapshot *s;
    for (i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--once")) once = 1;
        else if (!strcmp(argv[i], "--json")) json = 1;
        else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) { usage(); return 0; }
        else if (!strcmp(argv[i], "--interval") && i + 1 < argc) { interval = atof(argv[++i]); if (interval < 0.25) interval = 0.25; }
        else if (!strncmp(argv[i], "--interval=", 11)) { interval = atof(argv[i] + 11); if (interval < 0.25) interval = 0.25; }
        else { fprintf(stderr, "nettop: unknown argument: %s\n", argv[i]); return 1; }
    }
    signal(SIGPIPE, SIG_DFL);
    if (once || !isatty(STDIN_FILENO) || !isatty(STDOUT_FILENO)) {
        s = calloc(1, sizeof(Snapshot));
        if (!s) {
            fprintf(stderr, "nettop: out of memory\n");
            return 1;
        }
        collect_snapshot(s);
        if (json) print_json(s); else print_text(s);
        free(s);
        return 0;
    }
    tui(interval);
    return 0;
}
