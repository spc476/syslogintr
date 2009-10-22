
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

/*****************************************************************/

enum
{
  OPT_NONE,
  OPT_CONNQUEUE,
  OPT_LOGFILE,
  OPT_USER,
  OPT_GROUP,
  OPT_SCRIPT,
  OPT_FOREGROUND,
  OPT_LOG_IDENT,
  OPT_LOG_FACILITY,
  OPT_LOG_LEVEL,
  OPT_HELP
};

typedef struct listen_node
{
  void                    (*fn)(struct epoll_event *);
  int                       sock;
  struct sockaddr_storage   local;
} *ListenNode;

/******************************************************************/

ListenNode	udp_socket	(void);
ListenNode	log_socket	(void);
ListenNode	create_socket	(struct sockaddr *,socklen_t,void (*)(struct epoll_event *));
void		event_read	(struct epoll_event *);
void		default_interp	(struct sockaddr_storage *,const char *);
void		lua_interp	(struct sockaddr_storage *,const char *);
void		parse_options	(int,char *[]);
void		usage		(const char *);
void		drop_privs	(void);
void		daemon_init	(void);
void		load_script	(void);
int		map_str_to_int	(const char *,const char *const [],size_t);
void		handle_signal	(int);

/******************************************************************/

extern char *optarg;
extern int   optind;
extern int   opterr;
extern int   optopt;

const char  *g_logfile     = "/dev/log";
int          g_qsize       = MAX_EVENTS;
int          gf_log        = false;
int          gf_debug      = false;
int          gf_foreground = false;
const char  *g_slident     = "sli";
int          g_slfacility  = LOG_SYSLOG;
int          g_sllevel     = LOG_WARNING;
const char  *g_user        = "nobody";
const char  *g_group       = "nobody";
const char  *g_luacode;
lua_State   *g_L;
void	   (*g_interpret)(struct sockaddr_storage *,const char *) = default_interp;

const struct option c_options[] =
{
  { "conn-queue"   , required_argument , NULL           , OPT_CONNQUEUE } ,
  { "devlog"	   , no_argument       , &gf_log        , true          } ,
  { "debug"	   , no_argument       , &gf_debug      , true          } ,
  { "foreground"   , no_argument       , &gf_foreground , true          } ,
  { "logfile"	   , required_argument , NULL           , OPT_LOGFILE   } ,
  { "user"	   , required_argument , NULL	        , OPT_USER      } ,
  { "group"        , required_argument , NULL           , OPT_GROUP     } ,
  { "log-facility" , required_argument , NULL           , OPT_LOG_FACILITY } ,
  { "log-level"    , required_argument , NULL           , OPT_LOG_LEVEL } ,
  { "log-ident"    , required_argument , NULL           , OPT_LOG_IDENT } ,
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
  ListenNode         udp;
  ListenNode         log;
  int                queue;
  struct epoll_event ev;
  struct sigaction   act;
  struct sigaction   oact;
  int                rc;
  
  sigemptyset(&act.sa_mask);
  act.sa_handler = handle_signal;
  act.sa_flags   = 0;
  rc = sigaction(SIGINT,&act,&oact);
  if (rc == -1)
  {
    perror("sigaction(SIGINT)");
    exit(EXIT_FAILURE);
  }
  
  sigemptyset(&act.sa_mask);
  act.sa_handler = handle_signal;
  act.sa_flags   = 0;
  rc = sigaction(SIGUSR1,&act,&oact);
  if (rc == -1)
  {
    perror("sigaction(SIGUSR1)");
    exit(EXIT_FAILURE);
  }
  
  parse_options(argc,argv);
  openlog(g_slident,0,g_slfacility);
  
  if (gf_debug)
  {
    g_sllevel = LOG_DEBUG;
    usage(argv[0]);
    syslog(LOG_DEBUG,"Starting program");
  }    

  queue = epoll_create(g_qsize);
  if (queue == -1)
  {
    perror("epoll_create()");
    return EXIT_FAILURE;
  }
  
  syslog(LOG_DEBUG,"created epoll queue of size %d",g_qsize);
  
  udp = udp_socket();
  memset(&ev,0,sizeof(ev));
  ev.events   = EPOLLIN ;
  ev.data.ptr = udp;
  rc          = epoll_ctl(queue,EPOLL_CTL_ADD,udp->sock,&ev);
  if (rc == -1)
  {
    perror("epoll_ctl(ADD udp)");
    return EXIT_FAILURE;
  }
  
  syslog(LOG_DEBUG,"created UDP socket");
  
  if (gf_log)
  {
    log = log_socket();
    ev.events   = EPOLLIN;
    ev.data.ptr = log;
    rc          = epoll_ctl(queue,EPOLL_CTL_ADD,log->sock,&ev);
    if (rc == -1)
    {
      perror("epoll_ctl(ADD log)");
      return EXIT_FAILURE;
    }
    
    syslog(LOG_DEBUG,"created UNIX socket");
  }
  
  drop_privs();

  if (optind < argc)
  {
    g_L = lua_open();
    if (g_L == NULL)
    {
      fprintf(stderr,"could not initialize Lua\n");
      exit(EXIT_FAILURE);
    }
    
    lua_gc(g_L,LUA_GCSTOP,0);
    luaL_openlibs(g_L);
    lua_gc(g_L,LUA_GCRESTART,0);
   
    g_interpret = lua_interp; 
    g_luacode   = argv[optind];
    load_script();
  }
  else
    gf_foreground = true;
  
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

    events = epoll_wait(queue,list,MAX_EVENTS,-1);
    if ((events == -1) && (errno == EINTR)) continue;
    
    for (i = 0 ; i < events ; i++)
    {
      node = list[i].data.ptr;
      (*node->fn)(&list[i]);
    }
  }

  if (g_L)
    lua_close(g_L);
  
  if (gf_log)
  {
    close(log->sock);
    free(log);
  }

  close(udp->sock);
  free(udp);
  close(queue);
  closelog();
  
  return EXIT_SUCCESS;
}

/*************************************************************/

ListenNode udp_socket(void)
{
  struct sockaddr_in addr;
  
  memset(&addr,0,sizeof(addr));
  addr.sin_family      = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port        = htons(514);
  
  return create_socket((struct sockaddr *)&addr,sizeof(addr),event_read);
}

/**************************************************************/

ListenNode log_socket(void)
{
  struct sockaddr_un addr;
  ListenNode         node;
  
  unlink(g_logfile);
  
  memset(&addr,0,sizeof(addr));
  strcpy(addr.sun_path,g_logfile);
  addr.sun_family = AF_LOCAL;
  
  node = create_socket((struct sockaddr *)&addr,SUN_LEN(&addr),event_read);
  chmod(g_logfile,0666);
  
  return node;
}

/**************************************************************/

ListenNode create_socket(struct sockaddr *paddr,socklen_t saddr,void (*fn)(struct epoll_event *))
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
  listen->sock = socket(paddr->sa_family,SOCK_DGRAM,0);
  
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

  rc = bind(listen->sock,paddr,saddr);
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
  ListenNode              node;
  struct sockaddr_storage remote;
  socklen_t               remsize;
  ssize_t                 bytes;
  char                    buffer[BUFSIZ];
  
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
  (*g_interpret)(&remote,buffer);
}

/*********************************************************************/

void default_interp(struct sockaddr_storage *pss,const char *buffer)
{
  assert(pss    != NULL);
  assert(buffer != NULL);
  
  if (pss->ss_family == AF_INET)
  {
    struct sockaddr_in *r = (struct sockaddr_in *)pss; 
    printf("%15.15s:%d\t",inet_ntoa(r->sin_addr),ntohs(r->sin_port));
  }
  else 
    printf("%15.15s\t\t",g_logfile);

  div_t   faclev;
  int     value;
  char   *p;
  size_t  i;
  
  if (buffer[0] != '<')
  {
    printf("| %-8s %6s | bad input","","");
    return;
  }
  
  value = strtoul(&buffer[1],&p,10);
  if (*p != '>')
  {
    printf("| %-8s %6s | bad input","","");
    return;
  }
  
  p++;
  
  for (i = 0 ; p[i] != '\0' ; i++)
    if (iscntrl(p[i])) 
      p[i] = ' ';

  faclev = div(value,8);
  
  printf("| %-8s %6s | %s\n",c_facility[faclev.quot],c_level[faclev.rem],p);  
}

/*****************************************************************/

void lua_interp(struct sockaddr_storage *pss,const char *buffer)
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
  
  if (pss->ss_family == AF_INET)
  {
    struct sockaddr_in *r = (struct sockaddr_in *)pss;
    
    lua_pushstring(g_L,"remote");
    lua_pushboolean(g_L,true);
    lua_settable(g_L,-3);
    
    lua_pushstring(g_L,"host");
    lua_pushstring(g_L,inet_ntoa(r->sin_addr));
    lua_settable(g_L,-3);
    
    lua_pushstring(g_L,"port");
    lua_pushinteger(g_L,ntohs(r->sin_port));
    lua_settable(g_L,-3);
  }
  else
  {
    lua_pushstring(g_L,"remote");
    lua_pushboolean(g_L,false);
    lua_settable(g_L,-3);
    
    lua_pushstring(g_L,"host");
    lua_pushstring(g_L,g_logfile);
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
      case OPT_CONNQUEUE:
           g_qsize = strtoul(optarg,NULL,10);
           break;
      case OPT_LOGFILE:
           g_logfile = strdup(optarg);
           break;
      case OPT_LOG_FACILITY:
           g_slfacility = map_str_to_int(optarg,c_facility,MAX_FACILITY) << 3;
           break;
      case OPT_LOG_LEVEL:
           g_sllevel = map_str_to_int(optarg,c_level,MAX_LEVEL);
           break;
      case OPT_LOG_IDENT:
           g_slident = strdup(optarg);
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
        "\t--conn-queue n          (%d)\n"
        "\t--devlog                (false)\n"
        "\t--debug                 (false)\n"
        "\t--logfile file          (%s)\n"
        "\t--user uid              (%s)\n"
        "\t--group gid             (%s)\n"
        "\t--log-facility facility (%s)\n"
        "\t--log-level level       (%s)\n"
        "\t--log-ident id          (%s)\n"
        "\t--help\n",
        progname,
        g_qsize,
        g_logfile,
        g_user,
        g_group,
        c_facility[g_slfacility >> 3],	/* XXX */
        c_level[g_sllevel],
        g_slident
  );
}

/*******************************************************************/

void drop_privs(void)
{
  int rc;
  
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
  
  rc = getgrnam_r(g_group,&ginfo,gbuffer,gbufsize,&gresult);
  if (rc != 0)
  {
    perror("getgrnam_r()");
    exit(EXIT_FAILURE);
  }
  
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

