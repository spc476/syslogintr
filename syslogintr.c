
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>
#include <time.h>
#include <errno.h>
#include <stdbool.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/epoll.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <signal.h>
#include <syslog.h>
#include <pwd.h>
#include <grp.h>
#include <getopt.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#define MAX_FACILITY	24
#define MAX_LEVEL	 8
#define MAX_EVENTS	60

#define LOG_PORT	514
#define LOG_LOCAL	"/dev/log"
#define LOG_IPv4	"0.0.0.0"
#define LOG_IPv6	"::"
#define LOG_IDENT	"syslogl"

#define LUA_CODE	"minsys.lua"

/*****************************************************************/

enum
{
  OPT_NONE,
  OPT_USER,
  OPT_GROUP,
  OPT_LOG_IDENT,
  OPT_LOG_FACILITY,
  OPT_IPv4,
  OPT_IPv6,
  OPT_LOCAL,
  OPT_HELP
};

typedef union sockaddr_all
{
  struct sockaddr         ss;
  struct sockaddr_in      sin;
  struct sockaddr_in6     sin6;
  struct sockaddr_un      sun;
  struct sockaddr_storage ssto;
} sockaddr_all;

typedef struct listen_node
{
  void         (*fn)(struct epoll_event *);
  int            sock;
  sockaddr_all   local;
} *ListenNode;

/******************************************************************/

void		ipv4_socket		(const char *);
void		ipv6_socket		(const char *);
void		local_socket		(const char *);
ListenNode	create_socket		(sockaddr_all *,socklen_t,void (*)(struct epoll_event *));
void		event_read		(struct epoll_event *);
void		lua_interp		(sockaddr_all *,const char *);
void		parse_options		(int,char *[]);
void		usage			(const char *);
void		drop_privs		(void);
void		daemon_init		(void);
void		load_script		(void);
int		map_str_to_int		(const char *,const char *const [],size_t);
void		handle_signal		(int);
void		set_signal_handler	(int,void (*)(int));

/******************************************************************/

extern char *optarg;
extern int   optind;
extern int   opterr;
extern int   optopt;

int          g_queue;
const char  *g_slident     = LOG_IDENT;
int          g_slfacility  = LOG_SYSLOG;
const char  *g_luacode     = LUA_CODE;
const char  *g_user;
const char  *g_group;
int          gf_debug;
int          gf_foreground;
lua_State   *g_L;

const struct option c_options[] =
{
  { "ip"	   , optional_argument , NULL		, OPT_IPv4	} ,
  { "ip4"	   , optional_argument , NULL		, OPT_IPv4	} ,
  { "ipv4"	   , optional_argument , NULL		, OPT_IPv4	} ,
  { "ip6"	   , optional_argument , NULL		, OPT_IPv6	} ,
  { "ipv6"	   , optional_argument , NULL		, OPT_IPv6	} ,
  { "local"	   , optional_argument , NULL		, OPT_LOCAL     } ,  
  { "debug"	   , no_argument       , &gf_debug      , true          } ,
  { "foreground"   , no_argument       , &gf_foreground , true          } ,
  { "user"	   , required_argument , NULL	        , OPT_USER      } ,
  { "group"        , required_argument , NULL           , OPT_GROUP     } ,
  { "facility"     , required_argument , NULL           , OPT_LOG_FACILITY } ,
  { "ident"        , required_argument , NULL           , OPT_LOG_IDENT } ,
  { "help"         , no_argument       , NULL           , OPT_HELP      } ,
  
  { NULL           , 0                 , NULL           , 0             }
};

const char *const c_facility[] = 
{
  "kernel",
  "user",
  "mail",
  "daemon",
  "auth1",
  "syslog",
  "lpr",
  "news",
  "uucp",
  "cron1",
  "auth2",	/* also authpriv */
  "ftp",
  "ntp",
  "auth3",
  "auth4",
  "cron2",
  "local0",
  "local1",
  "local2",
  "local3",
  "local4",
  "local5",
  "local6",
  "local7"
};

const char *const c_level[] = 
{
  "emerg",
  "alert",
  "crit",
  "err",
  "warn",
  "notice",
  "info",
  "debug"
};

volatile sig_atomic_t mf_sigint;
volatile sig_atomic_t mf_sigusr1;

/***************************************************************/

int main(int argc,char *argv[])
{
  set_signal_handler(SIGINT, handle_signal);
  set_signal_handler(SIGUSR1,handle_signal);
  
  g_queue = epoll_create(MAX_EVENTS);
  if (g_queue == -1)
  {
    perror("epoll_create()");
    return EXIT_FAILURE;
  }
  
  parse_options(argc,argv);
  openlog(g_slident,0,g_slfacility);
  drop_privs();
  
  if (gf_debug)
  {
    usage(argv[0]);
    syslog(LOG_DEBUG,"Starting program");
  }
  
  g_L = lua_open();
  if (g_L == NULL)
  {
    perror("lua_open()");
    exit(EXIT_FAILURE);
  }
  
  lua_gc(g_L,LUA_GCSTOP,0);
  luaL_openlibs(g_L);
  lua_gc(g_L,LUA_GCRESTART,0);
  
  if (optind < argc)
    g_luacode = argv[optind];
  
  load_script();

  if (!gf_foreground)
    daemon_init();

  while(true)
  {
    struct epoll_event list[MAX_EVENTS];
    ListenNode         node;
    int                events;
    int                i;
    
    if (mf_sigint) break;
    if (mf_sigusr1)
    {
      load_script();
      mf_sigusr1 = 0;
    }

    events = epoll_wait(g_queue,list,MAX_EVENTS,-1);
    if ((events == -1) && (errno == EINTR)) continue;
    
    for (i = 0 ; i < events ; i++)
    {
      node = list[i].data.ptr;
      (*node->fn)(&list[i]);
    }
  }

  return EXIT_SUCCESS;
}

/*************************************************************/

void ipv4_socket(const char *taddr)
{
  ListenNode         ls;
  sockaddr_all       addr;
  struct epoll_event ev;
  int                rc;
  
  if (taddr == NULL)
    taddr = LOG_IPv4;
  
  memset(&addr,0,sizeof(addr));
  memset(&ev,  0,sizeof(ev));
  
  addr.sin.sin_family = AF_INET;
  inet_pton(AF_INET,taddr,&addr.sin.sin_addr.s_addr);
  addr.sin.sin_port = htons(LOG_PORT);
  ls = create_socket(&addr,sizeof(addr.sin),event_read);
  
  ev.events   = EPOLLIN;
  ev.data.ptr = ls;
  
  rc = epoll_ctl(g_queue,EPOLL_CTL_ADD,ls->sock,&ev);
  if (rc == -1)
    perror("epoll_ctl(ADD ipv4)");
}

/*************************************************************/

void ipv6_socket(const char *taddr)
{
  ListenNode         ls;
  sockaddr_all       addr;
  struct epoll_event ev;
  int                rc;
  
  if (taddr == NULL)
    taddr = LOG_IPv6;
  
  memset(&addr,0,sizeof(addr));
  memset(&ev,  0,sizeof(ev));
  
  addr.sin6.sin6_family = AF_INET6;
  inet_pton(AF_INET6,taddr,&addr.sin6.sin6_addr.s6_addr);
  addr.sin6.sin6_port = htons(LOG_PORT);
  ls = create_socket(&addr,sizeof(addr.sin6),event_read);
  
  ev.events   = EPOLLIN;
  ev.data.ptr = ls;
  
  rc = epoll_ctl(g_queue,EPOLL_CTL_ADD,ls->sock,&ev);
  if (rc == -1)
    perror("epoll_ctl(ADD ipv6)");
}

/**************************************************************/

void local_socket(const char *taddr)
{
  ListenNode         ls;
  sockaddr_all       addr;
  struct epoll_event ev;
  int                rc;
  
  if (taddr == NULL)
    taddr = LOG_LOCAL;
  
  rc = unlink(taddr);
  if (rc == -1)
  {
    perror(taddr);
    exit(EXIT_FAILURE);
  }
  
  memset(&addr,0,sizeof(addr));
  memset(&ev,  0,sizeof(ev));
  
  addr.sun.sun_family = AF_LOCAL;
  strcpy(addr.sun.sun_path,taddr);
  ls = create_socket(&addr,sizeof(addr.sun),event_read);
  
  ev.events   = EPOLLIN;
  ev.data.ptr = ls;
  rc = epoll_ctl(g_queue,EPOLL_CTL_ADD,ls->sock,&ev);
  if (rc == -1)
    perror("epoll_ctl(ADD local)");
}

/*******************************************************************/

ListenNode create_socket(sockaddr_all *paddr,socklen_t saddr,void (*fn)(struct epoll_event *))
{
  ListenNode          listen;
  int                 rc;
  int                 reuse = 1;
  
  assert(paddr != NULL);
  assert(saddr > 0);
  assert(fn    != NULL);
  
  listen = malloc(sizeof(struct listen_node));
  memset(listen,0,sizeof(struct listen_node));
  memcpy(&listen->local,paddr,saddr);
  
  listen->fn   = fn;
  listen->sock = socket(paddr->ss.sa_family,SOCK_DGRAM,0);
  
  rc = setsockopt(listen->sock,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(reuse));
  if (rc == -1)
  {
    perror("setsockopt()");
    exit(EXIT_FAILURE);
  }

  rc = fcntl(listen->sock,F_GETFL,0);
  if (rc == -1)
  {
    perror("fcntl(GETFL)");
    exit(EXIT_FAILURE);
  }
  
  rc = fcntl(listen->sock,F_SETFL,rc | O_NONBLOCK);
  if (rc == -1)
  {
    perror("fcntl(SETFL)");
    exit(EXIT_FAILURE);
  }

  rc = bind(listen->sock,&paddr->ss,saddr);
  if (rc == -1)
  {
    perror("bind()");
    exit(EXIT_FAILURE);
  }
  
  return listen;
}
  
/*****************************************************************/  

void event_read(struct epoll_event *ev)
{
  ListenNode   node;
  sockaddr_all remote;           
  socklen_t    remsize;
  ssize_t      bytes;
  char         buffer[BUFSIZ];
  
  assert(ev != NULL);
  
  memset(&remote,0,sizeof(remote));
  node    = ev->data.ptr;
  remsize = sizeof(remote);
  bytes   = recvfrom(node->sock,buffer,sizeof(buffer),0,(struct sockaddr *)&remote,&remsize);
  
  if (bytes == -1)
  {
    if (errno == EINTR) return;
    perror("recvfrom()");
    return;
  }
  
  buffer[bytes] = '\0';
  lua_interp(&remote,buffer);
}

/*********************************************************************/

void lua_interp(sockaddr_all *pss,const char *buffer)
{
  struct tm  dateread;
  time_t     now;
  div_t      faclev;
  int        value;
  char      *p;
  char      *q;
  size_t     i;
  int        rc;
  
  assert(pss    != NULL);
  assert(buffer != NULL);
  
  if (buffer[0] != '<')
  {
    syslog(LOG_DEBUG,"bad input");
    return;
  }
  
  value = strtoul(&buffer[1],&p,10);
  if (*p++ != '>')
  {
    syslog(LOG_DEBUG,"bad input");
    return;
  }
  
  for (i = 0 ; p[i] != '\0' ; i++)
    if (iscntrl(p[i]))
      p[i] = ' ';

  faclev = div(value,8);
  now    = time(NULL);
  localtime_r(&now,&dateread);
  
  lua_getglobal(g_L,"log");
  lua_newtable(g_L);

  lua_pushstring(g_L,"_RAW");	/* don't count on this */
  lua_pushstring(g_L,p);
  lua_settable(g_L,-3);

  lua_pushstring(g_L,"version");	/* syslog version */
  lua_pushinteger(g_L,0);		/* RFC3164 = v0   */
  lua_settable(g_L,-3);			/* RFC5424 = v1   */
  
  lua_pushstring(g_L,"facility");
  lua_pushstring(g_L,c_facility[faclev.quot]);
  lua_settable(g_L,-3);
  
  lua_pushstring(g_L,"level");
  lua_pushstring(g_L,c_level[faclev.rem]);
  lua_settable(g_L,-3);
  
  lua_pushstring(g_L,"timestamp");
  lua_pushinteger(g_L,now);
  lua_settable(g_L,-3);
  
  /*--------------------------------------------
  ; maybe there's a timestamp at the start,
  ; maybe there isn't ... try anyway 
  ;--------------------------------------------*/
  
  q = strptime(p,"%B %d %H:%M:%S",&dateread);
  
  if (q)
  {
    lua_pushstring(g_L,"logtimestatmp");
    lua_pushinteger(g_L,mktime(&dateread));
    lua_settable(g_L,-3);
    
    p = q + 1;
  }
  else
  {
    lua_pushstring(g_L,"logtimestamp");
    lua_pushinteger(g_L,now);
    lua_settable(g_L,-3);
  }
  
  /*---------------------------------------------
  ; extract program and PID.  If neither exist, 
  ; set program to "" and PID to 0.
  ;---------------------------------------------*/
  
  q = strchr(p,':');
  if (q)
  {
    char          *b;
    unsigned long  pid;
    
    b = strchr(p,'[');
    if (b)
    {
      pid = strtoul(b+1,NULL,10);
      *b = '\0';
    }
    else
      pid = 0;
    
    *q = '\0';
    
    lua_pushstring(g_L,"program");
    lua_pushstring(g_L,p);
    lua_settable(g_L,-3);
    
    lua_pushstring(g_L,"pid");
    lua_pushinteger(g_L,pid);
    lua_settable(g_L,-3);
    
    for (p = q + 1 ; *p && isspace(*p) ; p++)
      ;
  }
  else
  {
    lua_pushstring(g_L,"program");
    lua_pushstring(g_L,"");
    lua_settable(g_L,-3);
    
    lua_pushstring(g_L,"pid");
    lua_pushinteger(g_L,0);
    lua_settable(g_L,-3);
  }

  lua_pushstring(g_L,"msg");
  lua_pushstring(g_L,p);
  lua_settable(g_L,-3);
  
  if (pss->ss.sa_family == AF_INET)
  {
    char buffer[INET_ADDRSTRLEN];
    
    lua_pushstring(g_L,"remote");
    lua_pushboolean(g_L,true);
    lua_settable(g_L,-3);
    
    lua_pushstring(g_L,"host");
    lua_pushstring(g_L,inet_ntop(AF_INET,&pss->sin.sin_addr,buffer,INET_ADDRSTRLEN));
    lua_settable(g_L,-3);
    
    lua_pushstring(g_L,"port");
    lua_pushinteger(g_L,ntohs(pss->sin.sin_port));
    lua_settable(g_L,-3);
  }
  else if (pss->ss.sa_family == AF_INET6)
  {
    char buffer[INET6_ADDRSTRLEN];
    
    lua_pushstring(g_L,"remote");
    lua_pushboolean(g_L,true);
    lua_settable(g_L,-3);
    
    lua_pushstring(g_L,"host");
    lua_pushstring(g_L,inet_ntop(AF_INET6,&pss->sin6.sin6_addr,buffer,INET6_ADDRSTRLEN));
    lua_settable(g_L,-3);
    
    lua_pushstring(g_L,"port");
    lua_pushinteger(g_L,ntohs(pss->sin6.sin6_port));
    lua_settable(g_L,-3);
  }
  else
  {
    lua_pushstring(g_L,"remote");
    lua_pushboolean(g_L,false);
    lua_settable(g_L,-3);
    
    lua_pushstring(g_L,"host");
    lua_pushstring(g_L,"(localsocket)");
    lua_settable(g_L,-3);
    
    lua_pushstring(g_L,"port");
    lua_pushinteger(g_L,-1);
    lua_settable(g_L,-3);
  }
  
  rc = lua_pcall(g_L,1,0,0);
  if (rc != 0)
  {
    const char *err = lua_tostring(g_L,1);
    syslog(LOG_DEBUG,"Lua ERROR: (%d) %s",rc,err);
  }
}

/****************************************************************/

void parse_options(int argc,char *argv[])
{
  int option = 0;
  
  assert(argc >  0);
  assert(argv != NULL);
  
  while(true)
  {
    switch(getopt_long_only(argc,argv,"",c_options,&option))
    {
      case EOF:      
           return;
      case OPT_NONE: 
           break;
      case OPT_IPv4:
           ipv4_socket(optarg);
           break;
      case OPT_IPv6:
           ipv6_socket(optarg);
           break;
      case OPT_LOCAL:
           local_socket(optarg);
           break;
      case OPT_LOG_FACILITY:
           g_slfacility = map_str_to_int(optarg,c_facility,MAX_FACILITY) << 3;
           break;
      case OPT_LOG_IDENT:
           g_slident = strdup(optarg);
           break;
      case OPT_USER:
           g_user = strdup(optarg);
           break;
      case OPT_GROUP:
           g_group = strdup(optarg);
           break;
      case OPT_HELP:
           usage(argv[0]);
           exit(EXIT_FAILURE);
      default:
           assert(0);
           break;
    }
  }
}

/*****************************************************************/

void usage(const char *progname)
{
  assert(progname != NULL);
  
  fprintf(
  	stderr,
        "usage: %s [options...] [luafile]\n"
        "\t--ip    [ipaddr]          bind to IP address (any)\n"
        "\t--ip4   [ipaddr]                  \"\n"
        "\t--ipv4  [ipaddr]                  \"\n"
        "\t--ip6   [ip6addr]         bind to IPv6 address (any)\n"
        "\t--ipv6  [ip6addr]                  \"\n"
        "\t--local [localsocket]     bind to local socket (/dev/log)\n"
        "\t--debug                   debug info\n"
        "\t--foreground              run in foreground\n"
        "\t--user  <username>        user to run as (no default)\n"
        "\t--group <groupname>       group to run as (no default)\n"
        "\t--facility <facility>     syslog facility (syslog)\n"
        "\t--ident    <id>           syslog ident    (syslogl)\n"
        "\t--help                    this message\n"
        "\n",
        progname
  );
}

/*******************************************************************/

void drop_privs(void)
{
  int rc;
  
  if (g_user == NULL)	/* if no user specified, we won't drop */
    return;
    
  if (getuid() != 0)	/* if not root, we can't drop privs */
    return;

  long           ubufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
  char           ubuffer[ubufsize];
  struct passwd  uinfo;
  struct passwd *uresult;
  
  rc = getpwnam_r(g_user,&uinfo,ubuffer,ubufsize,&uresult);
  if (rc != 0)
  {
    perror("getpwnam_r()");
    exit(EXIT_FAILURE);
  }
  
  long          gbufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
  char          gbuffer[gbufsize];
  struct group  ginfo;
  struct group *gresult;
  
  if (g_group == NULL)
  {
    rc = getgrnam_r(g_group,&ginfo,gbuffer,gbufsize,&gresult);
    if (rc != 0)
    {
      perror("getgrnam_r()");
      exit(EXIT_FAILURE);
    }
  }
  else
    ginfo.gr_gid = uinfo.pw_gid;

  rc = setgid(ginfo.gr_gid);
  if (rc  == -1)
  {
    perror("setgid()");
    exit(EXIT_FAILURE);
  }
  
  rc = setuid(uinfo.pw_uid);
  if (rc == -1)
  {
    perror("setuid()");
    exit(EXIT_FAILURE);
  }
  
  syslog(LOG_DEBUG,"dropped privs to %s:%s",g_user,g_group);
}

/*************************************************************************/

void load_script(void)
{
  int rc;
  
  rc = luaL_loadfile(g_L,g_luacode);
  if (rc != 0)
  {
    const char *err = lua_tostring(g_L,1);
    syslog(LOG_DEBUG,"Lua ERROR: (%d) %s",rc,err);
    return;
  }
  
  rc = lua_pcall(g_L,0,LUA_MULTRET,0);
  if (rc != 0)
  {
    const char *err = lua_tostring(g_L,1);
    syslog(LOG_DEBUG,"Lua ERROR: (%d) %s",rc,err);
    return;
  }
  
  syslog(LOG_DEBUG,"loaded script %s\n",g_luacode);
}

/*************************************************************************/

void daemon_init(void)
{
  pid_t pid;
  
  pid = fork();
  if (pid == (pid_t)-1)
  {
    perror("fork()");
    exit(EXIT_FAILURE);
  }
  else if (pid != 0)	/* parent goes bye bye */
    exit(EXIT_SUCCESS);

  setsid();
  syslog(LOG_DEBUG,"gone into daemon mode");
  
  
  if (g_L)
  {
    lua_getglobal(g_L,"io");
  
    lua_getfield(g_L,-1,"close");
    lua_getfield(g_L,-2,"stdin");
    lua_call(g_L,1,0);
    
    lua_getfield(g_L,-1,"close");
    lua_getfield(g_L,-2,"stdout");
    lua_call(g_L,1,0);
    
    lua_getfield(g_L,-1,"close");
    lua_getfield(g_L,-2,"stderr");
    lua_call(g_L,1,0);
    
    close(STDERR_FILENO);
    close(STDOUT_FILENO);
    close(STDIN_FILENO);
    
    lua_getfield(g_L,-1,"open");
    lua_pushstring(g_L,"/dev/null");
    lua_pushstring(g_L,"r");
    lua_call(g_L,2,1);
    lua_setfield(g_L,-2,"stdin");
    
    lua_getfield(g_L,-1,"open");
    lua_pushstring(g_L,"/dev/null");
    lua_pushstring(g_L,"w");
    lua_call(g_L,2,1);
    lua_setfield(g_L,-2,"stdout");
    
    lua_getfield(g_L,-1,"open");
    lua_pushstring(g_L,"/dev/null");
    lua_pushstring(g_L,"w");
    lua_call(g_L,2,1);
    lua_setfield(g_L,-2,"stderr");
    
    lua_pop(g_L,lua_gettop(g_L));
    syslog(LOG_DEBUG,"reopened io.stdin, io.stdout and io.stderr");
  }
}

/***********************************************************************/

int map_str_to_int(const char *name,const char *const list[],size_t size)
{
  assert(name != NULL);
  assert(list != NULL);
  assert(size >  0);
  
  for (size_t i = 0 ; i < size ; i++)
  {
    if (strcmp(name,list[i]) == 0)
      return i;
  }
  return -1;
}

/***********************************************************************/

void handle_signal(int sig)
{
  switch(sig)
  {
    case SIGINT:  mf_sigint  = 1; break;
    case SIGUSR1: mf_sigusr1 = 1; break;
    default: break;
  }
}

/**********************************************************************/

void set_signal_handler(int sig,void (*handler)(int))
{
  struct sigaction act;
  struct sigaction oact;
  int              rc;
  
  sigemptyset(&act.sa_mask);
  act.sa_handler = handler;
  act.sa_flags   = 0;
  rc = sigaction(sig,&act,&oact);
  if (rc == -1)
  {
    perror("sigaction()");
    exit(EXIT_FAILURE);
  }
}

/**************************************************************************/

