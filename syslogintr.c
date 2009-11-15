/*********************************************************************
*
* Copyright 2009 by Sean Conner.  All Rights Reserved.
*
* This program is free software; you can redistribute it and/or
* modify it under the terms of the GNU General Public License
* as published by the Free Software Foundation; either version 2
* of the License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
*
* Comments, questions and criticisms can be sent to: sean@conman.org
*
*********************************************************************/

/*******************************************************************
*
* SyslogInterpreter - a syslog replacement.
*
* This binds to the various syslog sockets, collects syslog requests,
* and then passes them on to a Lua function for handling.  The C code
* will construct a Lua table with the following fields:
*
*	version		integer = 0
*	facility	string
*	level		string
*	timestamp	as from os.time()
*	logtimestamp	as from os.time() [1]
*	pid		integer (0 if not available)  [2]
*	program		string  ("" if not available) [3]
*	msg		actual string
*	remote		boolean
*	host		string [4]
*	origin		string  ("" if not available) [6]
*	port		integer (-1 if not available) [5]
*
* and then pass it to a Lua function called log().  That function can then
* do whatever it wants with the information.
*
* Sending this program a SIGUSR1 will cause it to reload the given script,
* meaning you can extend the script, then have the changes take affect
* without restarting the program.
*
* Sending this program a SIGUSR2 will cause it to look for a Lua function
* called user_signal() and call that.  user_signal() has no parameters,
* and returns no parameters.
*
* You can also schedule a function to run periodically with the Lua 
* function alarm(n).  The pameter is either a number, which is the number 
* of seconds between invocations of the supplied alarm_handler() function,
* or a string, which has a format of "<number>s" (for number of seconds), 
* "<number>m" (for number of minutes), "<number>h" (for number of hours)
* or "<number>d" (for number of days).  The functino alarm_handler()
* takes no parameters, nor returns any paramters.
*
* [1]	if the incoming syslog request has a timestamp, this will contain
*	it, otherwise, it's equal to the timestamp field.
*
* [2]	if the incoming syslog request has a PID field.
*
* [3]	if the incoming syslog request has a program field.
*
* [4]	IP address (IPv4 or IPv6) of the request.  If it's from the local
*	socket (defaults to "/dev/log" under Linux) this will be the
*	filename of the localsocket.
*
* [5]	Remote port of the request, or 0 if from the localsocket.
*
* [6]	May be part of the original message.  If not part of the
*	original message, it will be "".
*
************************************************************************/

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

struct sysstring
{
  size_t      size;
  const char *text;
};

struct msg
{
  int              version;
  struct sysstring raw;
  struct sysstring host;
  struct sysstring origin;
  int              port;
  bool             remote;
  time_t           timestamp;
  time_t           logtimestamp;
  struct sysstring program;
  int              pid;  
  int              facility;
  int              level;
  struct sysstring msg;
};

/******************************************************************/

void		ipv4_socket		(const char *);
void		ipv6_socket		(const char *);
void		local_socket		(const char *);
ListenNode	create_socket		(sockaddr_all *,socklen_t,void (*)(struct epoll_event *));
void		event_read		(struct epoll_event *);
void		lua_interp		(sockaddr_all *,sockaddr_all *,const char *);
void		process_msg		(const struct msg *const);
void		parse_options		(int,char *[]);
void		usage			(const char *);
void		drop_privs		(void);
void		daemon_init		(void);
void		load_script		(void);
int		map_str_to_int		(const char *,const char *const [],size_t);
void		handle_signal		(int);
void		set_signal_handler	(int,void (*)(int));
int		syslogintr_alarm	(lua_State *);

/******************************************************************/

extern char *optarg;
extern int   optind;
extern int   opterr;
extern int   optopt;

int          g_queue;
unsigned int g_alarm;
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

struct sysstring c_null = { 0 , "" } ;

volatile sig_atomic_t mf_sigint;
volatile sig_atomic_t mf_sigusr1;
volatile sig_atomic_t mf_sigusr2;
volatile sig_atomic_t mf_sigalarm;

/***************************************************************/

int main(int argc,char *argv[])
{
  set_signal_handler(SIGINT, handle_signal);
  set_signal_handler(SIGUSR1,handle_signal);
  set_signal_handler(SIGUSR2,handle_signal);
  set_signal_handler(SIGALRM,handle_signal);
  
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
  lua_register(g_L,"alarm",syslogintr_alarm);
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

    if (mf_sigusr2)
    {
      mf_sigusr2 = 0;
      lua_getglobal(g_L,"user_signal");
      if (lua_isfunction(g_L,1))
      {
        int rc = lua_pcall(g_L,0,0,0);        
        if (rc != 0)
        {
          const char *err = lua_tostring(g_L,1);
          syslog(LOG_DEBUG,"Lua ERROR: (%d) %s",rc,err);
        }
      }
      else
        lua_pop(g_L,1);
    }
    
    if (mf_sigalarm)
    {
      mf_sigalarm = 0;
      lua_getglobal(g_L,"alarm_handler");
      if (lua_isfunction(g_L,1))
      {
        int rc = lua_pcall(g_L,0,0,0);
        if (rc != 0)
        {
          const char *err = lua_tostring(g_L,1);
          syslog(LOG_DEBUG,"Lua ERROR: (%d) %s",rc,err);
        }
        alarm(g_alarm);
      }
      else
      {
        lua_pop(g_L,1);
        syslog(LOG_ERR,"Alarm set, but no action when trigger!");
      }
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
  
  if (bytes > 1024)
    bytes = 1024;
  
  buffer[bytes] = '\0';
  
  for (size_t i = 0 ; buffer[i] != '\0'; i++)
    if (iscntrl(buffer[i]))
      buffer[i] = ' ';
      
  lua_interp(&node->local,&remote,buffer);
}

/*********************************************************************/

void lua_interp(sockaddr_all *ploc,sockaddr_all *pss,const char *buffer)
{
  struct msg msg;
  char       host[BUFSIZ];
  char       raw [1025];
  struct tm  dateread;
  time_t     now;
  div_t      faclev;
  int        value;
  char      *p;
  char      *q;
  size_t     i;
  int        rc;
  
  assert(ploc   != NULL);
  assert(pss    != NULL);
  assert(buffer != NULL);
  
  memset(raw,0,sizeof(raw));
  memcpy(raw,buffer,1024);
  
  now = time(NULL);
  localtime_r(&now,&dateread);
  
  msg.version      = 0;
  msg.raw.size     = strlen(buffer);
  msg.raw.text     = raw;
  msg.timestamp    = now;
  msg.logtimestamp = now;
  msg.program      = c_null;
  msg.hostname     = c_null;
  msg.pid          = 0;
  
  if (pss->ss.sa_family == AF_INET)
  {
    inet_ntop(AF_INET,&pss->sin.sin_addr,host,INET_ADDRSTRLEN);
    
    msg.remote    = true;
    msg.host.size = strlen(host);
    msg.host.text = host;
    msg.port      = ntohs(pss->sin.sin_port);
  }
  else if (pss->ss.sa_family == AF_INET6)
  {
    inet_ntop(AF_INET6,&pss->sin6.sin6_addr,host,INET6_ADDRSTRLEN);
    
    msg.remote    = true;
    msg.host.size = strlen(host);
    msg.host.text = host;
    msg.port      = ntohs(pss->sin6.sin6_port);
  }
  else
  {
    msg.remote    = false;
    msg.host.size = strlen(ploc->sun.sun_path);
    msg.host.text = ploc->sun.sun_path;
    msg.port      = -1;
  }
  
  if (buffer[0] != '<')
  {
    msg.facility = 1;	/* LOG_USER */
    msg.level    = 5;	/* LOG_NOTICE */
    msg.msg      = msg.raw;
    
    process_msg(&msg);
    return;
  }
  
  value = strtoul(&buffer[1],&p,10);
  if (*p++ != '>')
  {
    msg.facility = 1;	/* LOG_USER */
    msg.level    = 5;	/* LOG_NOTICE */
    msg.msg      = msg.raw;
    
    process_msg(&msg);
    return;
  }
  
  faclev = div(value,8);
  
  msg.facility = faclev.quot;
  msg.level    = faclev.rem;
  
  /*---------------------------------------------
  ; check for a supplied timestamp.
  ;---------------------------------------------*/
  
  q = strptime(p,"%B %d %H:%M:%S",&dateread);
  
  if (q)
  {
    msg.logtimestamp = mktime(&dateread);
    if (*q != ' ')
    {
      msg.facility = LOG_USER;
      msg.level    = LOG_NOTICE;
      msg.msg      = msg.raw;
      process_msg(&msg);
      return;
    }
    p = q + 1;
  }
  
  /*--------------------------------------------
  ; check for origin/program name/pid fields
  ; (technically, the PID field isn't part of
  ; RFC3164, and is technically part of the CONTENT
  ; portion of the message, but hey, a lot of
  ; Unix programs set it.  So it makes sense.
  ;-----------------------------------------------*/
  
  q = strchr(p,':');
  if (q)
  {
    char *b;
    
    b = memchr(p,' ',(size_t)(q - p));
    if (b != NULL)
    {
      msg.origin.text = p;
      msg.origin.size = (size_t)(b - p);
      p = b + 1;
    }
    
    b = memchr(p,'[',(size_t)(q - p));
    if (b)
    {
      msg.pid = strtoul(b + 1,NULL,10);
      *b = '\0';
    }
    
    *q = '\0';
    
    msg.program.text = p;
    msg.program.size = (size_t)(q - p);
    
    for (p = q + 1 ; *p && isspace(*p) ; p++)
      ;      
  }
  
  /*---------------------------------------------------
  ; whatever remains, however small, is the msg.
  ;---------------------------------------------------*/
  
  msg.msg.text = p;
  msg.msg.size = strlen(p);
  
  process_msg(&msg);
}

/***********************************************************************/

void process_msg(const struct msg *const pmsg)
{
  const char *err;
  int         rc;
  
  assert(pmsg != NULL);
  
  lua_getglobal(g_L,"log");
  lua_newtable(g_L);
  
  lua_pushliteral(g_L,"version");
  lua_pushinteger(g_L,pmsg->version);
  lua_settable(g_L,-3);
  
  lua_pushliteral(g_L,"_RAW");
  lua_pushlstring(g_L,pmsg->raw.text,pmsg->raw.size);
  lua_settable(g_L,-3);
  
  lua_pushliteral(g_L,"host");
  lua_pushlstring(g_L,pmsg->host.text,pmsg->host.size);
  lua_settable(g_L,-3);
  
  lua_pushliteral(g_L,"origin");
  lua_pushlstring(g_L,pmsg->hostname.text,pmsg->hostname.size);
  lua_settable(g_L,-3);
  
  lua_pushliteral(g_L,"port");
  lua_pushinteger(g_L,pmsg->port);
  lua_settable(g_L,-3);
  
  lua_pushliteral(g_L,"remote");
  lua_pushboolean(g_L,pmsg->remote);
  lua_settable(g_L,-3);
    
  lua_pushliteral(g_L,"timestamp");
  lua_pushinteger(g_L,pmsg->timestamp);
  lua_settable(g_L,-3);
  
  lua_pushliteral(g_L,"logtimestamp");
  lua_pushinteger(g_L,pmsg->logtimestamp);
  lua_settable(g_L,-3);
  
  lua_pushliteral(g_L,"program");
  lua_pushlstring(g_L,pmsg->program.text,pmsg->program.size);
  lua_settable(g_L,-3);
  
  lua_pushliteral(g_L,"pid");
  lua_pushinteger(g_L,pmsg->pid);
  lua_settable(g_L,-3);
  
  lua_pushliteral(g_L,"facility");
  lua_pushstring(g_L,c_facility[pmsg->facility]);
  lua_settable(g_L,-3);
  
  lua_pushliteral(g_L,"level");
  lua_pushstring(g_L,c_level[pmsg->level]);
  lua_settable(g_L,-3);
  
  lua_pushliteral(g_L,"msg");
  lua_pushlstring(g_L,pmsg->msg.text,pmsg->msg.size);
  lua_settable(g_L,-3);
  
  rc = lua_pcall(g_L,1,0,0);
  if (rc != 0)
  {
    err = lua_tostring(g_L,1);
    syslog(LOG_ERR,"Lua ERROR(%d): %s",rc,err);
  }
}

/**********************************************************************/

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
    case SIGINT:  mf_sigint   = 1; break;
    case SIGUSR1: mf_sigusr1  = 1; break;
    case SIGUSR2: mf_sigusr2  = 1; break;
    case SIGALRM: mf_sigalarm = 1; break;
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

int syslogintr_alarm(lua_State *L)
{
  int pcount;
  
  pcount = lua_gettop(L);
  if (pcount == 0)
    return luaL_error(L,"not enough arguments");
  else if (pcount > 1)
    return luaL_error(L,"too many arguments");
  
  if (lua_isnumber(L,1))
    g_alarm = lua_tointeger(L,1);
  else if (lua_isstring(L,1))
  {
    const char *v = lua_tostring(L,1);
    char       *p;
    
    g_alarm = strtoul(v,&p,10);
    switch(*p)
    {
      case 's': break;
      case 'm': g_alarm *=    60; break;
      case 'h': g_alarm *=  3600; break;
      case 'd': g_alarm *= 86400; break;
      default:  break;
    }
  }
  
  alarm(g_alarm);
  lua_pop(L,1);
  return 0;
}

/***********************************************************************/
