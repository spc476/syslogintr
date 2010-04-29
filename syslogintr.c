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
* This binds to the various syslog sockets, collects syslog requests, and
* then passes them on to a Lua function for handling.  The C code will
* construct a Lua table with the following fields:
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
*	relay		string  ("" if not available) [6]
*	port		integer (-1 if not available) [5]
*
* and then pass it to a Lua function called log().  That function can then
* do whatever it wants with the information.
*
* Sending this program a SIGUSR1 will cause it to reload the given script,
* meaning you can extend the script, then have the changes take affect
* without restarting the program.
*
* Sending this program a SIGHUP will cause it to look for a Lua function
* called reload_signal() and call that.  reload_signal() has no parameters,
* and returns no parameters.
*
* You can also schedule a function to run periodically with the Lua function
* alarm(n).  The parameter is either a number, which is the number of
* seconds between invocations of the supplied alarm_handler() function, or a
* string, which has a format of "<number>s" (for number of seconds),
* "<number>m" (for number of minutes), "<number>h" (for number of hours) or
* "<number>d" (for number of days).  The functino alarm_handler() takes no
* parameters, nor returns any paramters.
*
* There are also two Lua variables defined:
*
*	scriptpath	- the full path to the script being run
*	script		- the basename of the script being run
*
* To compile (assuming the Lua header files and library are installed):
*
*	Linux:
* 	gcc -std=c99 -rdynamic -g -o syslogintr syslogintr.c -ldl -lm -llua
*
*	Mac-OS/X
*	gcc -std=c99 -g -o syslogintr syslogintr.c -ldl -lm -llua
*
*	OpenBSD
*	gcc -std=c99 -rdynamic -g -o syslogintr syslogintr.c -lm -llua
*
*	Solaris (using native Sun compiler)
*	cc -xc99 -g -o syslogintr syslogintr.c -llua -ldl -lm -lsocket -lnsl
*
* [1]	if the incoming syslog request has a timestamp, this will contain
*	it, otherwise, it's equal to the timestamp field.
*
* [2]	if the incoming syslog request has a PID field.
*
* [3]	if the incoming syslog request has a program field.
*
* [4]	IP address (IPv4 or IPv6) of the request.  If it's from a local
*	socket this will be the filename of the localsocket.
*
* [5]	Remote port of the request, or 0 if from the localsocket.
*
* [6]	The message is being relayed from an original source.  If that
*	is the case, then host will be set to the original source, and
*	relay will be set to the device that sent us the message.  If
*	the device was the original sender, then relay will be "".
************************************************************************/

#define _GNU_SOURCE
#define _POSIX_PTHREAD_SEMANTICS

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>

#include <syslog.h>
#include <signal.h>
#include <pwd.h>
#include <grp.h>
#include <getopt.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#define MAX_FACILITY	24
#define MAX_LEVEL	 8
#define MAX_SOCKETS	18
#define MAX_MSGLEN	1024

#define LOG_PORT	514
#define LOG_LOCAL	"/dev/log"
#define LOG_IPv4	"0.0.0.0"
#define LOG_IPv6	"::"

#define LUA_CODE	"/usr/local/sbin/syslog.lua"
#define LUA_UD_HOST	"SOCKADDR"

#define PID_FILE	"/var/run/syslogd.pid"
#define DEV_NULL	"/dev/null"

/************************************************************************
*
* And now the ugly, non-portable bits.  This stuff bites and I hate that
* I have to do this, but alas, if I want this to compile on stuff other
* than my own system ... 
*
************************************************************************/

#ifdef __APPLE__
#  include <libgen.h>
#  undef LOG_LOCAL
#  define LOG_LOCAL	"/var/run/syslog"
#  ifndef AI_NUMERICSERV
#    define AI_NUMERICSERV	0
#  endif
#  ifndef _SC_GETPW_R_SIZE_MAX
#    define sysconf(x)	BUFSIZ
#  endif
#endif

#ifdef __OpenBSD__
#  include <libgen.h>
#endif

#ifdef __SunOS
#  include <libgen.h>
#  include <sys/un.h>
#  define AF_LOCAL	AF_UNIX
#endif

/*****************************************************************/

enum
{
  OPT_NONE	= '\0',
  OPT_USER	= 'u',
  OPT_GROUP	= 'g',
  OPT_IPv4	= '4',
  OPT_IPv6	= '6',
  OPT_IPv4int   = 'i',
  OPT_IPv6int   = 'I',
  OPT_LOCAL	= 'l',
  OPT_SOCKET	= 's',
  OPT_FG	= 'f',
  OPT_PATH	= 'p',
  OPT_CPATH	= 'c',
  OPT_HELP	= 'h',
  OPT_ERR       = '?'
};

typedef struct status
{
  bool  okay;
  int   err;
  char *msg;
} Status;

typedef union sockaddr_all
{
  struct sockaddr         ss;
  struct sockaddr_in      sin;
  struct sockaddr_in6     sin6;
  struct sockaddr_un      ssun;
  struct sockaddr_storage ssto;
} sockaddr_all;

typedef struct socket_node
{
  int          sock;
  sockaddr_all local;
} *SocketNode;

struct sysstring
{
  size_t      size;
  const char *text;
};

typedef struct node
{
  struct node *ln_Succ;
  struct node *ln_Pred;
} Node;

typedef struct list
{
  struct node *lh_Head;
  struct node *lh_Tail;
  struct node *lh_TailPred;
} List;

struct msg
{
  Node             node;	  /* used to internally queue log msgs	*/
  int              version;	  /* syslog version---RFC3164=0		*/
  struct sysstring raw;		  /* raw message (debugging purposes)	*/
  struct sysstring host;	  /* address of original sending host	*/
  struct sysstring relay;	  /* address of host that sent msg	*/
  int              port;	  /* UDP port of sending host		*/
  bool             remote;	  /* true if syslog from remote		*/
  time_t           timestamp;	  /* timestamp of received syslog	*/
  time_t           logtimestamp;  /* original timestamp 		*/
  struct sysstring program;	  /* program that generated syslog	*/
  int              pid;		  /* process id of said program		*/
  int              facility;	
  int              level;
  struct sysstring msg;		  /* syslog message			*/
};

/******************************************************************/

Status		 ipv4_socket		(const char *);
Status		 ipv6_socket		(const char *);
Status		 local_socket		(const char *);
Status		 create_socket		(SocketNode,socklen_t);
void		 event_read		(SocketNode);
void		 syslog_interp		(sockaddr_all *,sockaddr_all *,const char *,const char *);
void		 process_msg		(const struct msg *const);
Status		 globalv_init		(int,char *[]);
void		 usage			(const char *);
Status		 drop_privs		(void);
Status		 daemon_init		(void);
void		 load_script		(void);
int		 map_str_to_int		(const char *,const char *const [],size_t);
void		 handle_signal		(int);
Status		 set_signal_handler	(int,void (*)(int));
int		 syslogintr_alarm	(lua_State *);
int		 syslogintr_ud__toprint	(lua_State *);
int		 syslogintr_host	(lua_State *);
int		 syslogintr_relay	(lua_State *);
void		 call_optional_luaf	(const char *);
void		 internal_log		(int,const char *,...);
Node		*ListRemHead		(List *const);
void		 NodeInsert		(Node *const,Node *const);
void		 NodeRemove		(Node *const);
void		 add_lua_path		(const char *,const char *);

/******************************************************************/

static inline void ListInit(List *const pl)
{
  assert(pl != NULL);
  
  pl->lh_Head     = (Node *)&pl->lh_Tail;
  pl->lh_Tail     = NULL;
  pl->lh_TailPred = (Node *)&pl->lh_Head;
}

static inline void ListAddTail(List *const pl,Node *const pn)
{
  assert(pl != NULL);
  assert(pn != NULL);
  
  NodeInsert(pl->lh_TailPred,pn);
}

static inline Node *ListGetHead(List *const pl)
{
  assert(pl          != NULL);
  assert(pl->lh_Head != NULL);
  
  return pl->lh_Head;
}

static inline bool NodeValid(Node *const pn)
{
  assert(pn != NULL);
  
  if (pn->ln_Succ == NULL) return false;
  if (pn->ln_Pred == NULL) return false;
  return true;
}

static inline Status retstatus(bool okay,int err,char *msg)
{
  assert(msg != NULL);
  
  return (Status){
                   .okay = okay,
                   .err  = err,
                   .msg  = msg
                 };
}

/******************************************************************/

extern char *optarg;
extern int   optind;
extern int   opterr;
extern int   optopt;

unsigned int         g_alarm;
const char          *g_luacode     = LUA_CODE;
const char          *g_user;
const char          *g_group;
const char          *g_lpath;
const char          *g_lcpath;
int                  gf_foreground;
lua_State           *g_L;
struct socket_node   g_sockets[MAX_SOCKETS];
size_t               g_maxsocket;
size_t               g_ipv4;
size_t               g_ipv6;
struct sysstring     g_logtag;
List                 g_intlog;

const struct option c_options [] =
{
  { "foreground"   , no_argument       , NULL		, OPT_FG        } ,
  { "ip"	   , no_argument       , NULL		, OPT_IPv4	} ,
  { "ip4"	   , no_argument       , NULL		, OPT_IPv4	} ,
  { "ipv4"	   , no_argument       , NULL		, OPT_IPv4	} ,
  { "ipaddr"       , required_argument , NULL		, OPT_IPv4int	} ,
  { "ip4addr"	   , required_argument , NULL		, OPT_IPv4int	} ,
  { "ipv4addr"	   , required_argument , NULL		, OPT_IPv4int	} ,
  { "ip6"	   , no_argument       , NULL		, OPT_IPv6	} ,
  { "ipv6"	   , no_argument       , NULL		, OPT_IPv6	} ,
  { "ip6addr"	   , required_argument , NULL		, OPT_IPv6int	} ,
  { "ipv6addr"     , required_argument , NULL		, OPT_IPv6int   } ,
  { "local"	   , no_argument       , NULL		, OPT_LOCAL     } ,
  { "socket"	   , required_argument , NULL		, OPT_SOCKET	} ,
  { "user"	   , required_argument , NULL	        , OPT_USER      } ,
  { "group"        , required_argument , NULL           , OPT_GROUP     } ,
  { "lua-path"	   , required_argument , NULL		, OPT_PATH	} ,
  { "lua-cpath"    , required_argument , NULL		, OPT_CPATH	} ,
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

const struct sysstring c_null = { 0 , "" } ;
const struct status    c_okay = { true , 0 , "" } ;

volatile sig_atomic_t mf_sigint;
volatile sig_atomic_t mf_sigusr1;
volatile sig_atomic_t mf_sighup;
volatile sig_atomic_t mf_sigalarm;

/***************************************************************/

int main(int argc,char *argv[])
{
  Status  status;
  FILE   *fppid;
    
  status = globalv_init(argc,argv);
  if (!status.okay)
  {
    if (status.err != 0)
      perror(status.msg);
    return EXIT_FAILURE;
  }

  if (!gf_foreground)
  {
    status = daemon_init();
    if (!status.okay)
    {
      perror(status.msg);
      return EXIT_FAILURE;
    }
  }

  fppid = fopen(PID_FILE,"w");
  if (fppid)
  {
    fprintf(fppid,"%lu\n",(unsigned long)getpid());
    fclose(fppid);
  }

  status = drop_privs();
  if (!status.okay)
  {
    perror(status.msg);
    return EXIT_FAILURE;
  }

  g_L = lua_open();
  if (g_L == NULL)
  {
    perror("lua_open()");
    return EXIT_FAILURE;
  }
  
  lua_gc(g_L,LUA_GCSTOP,0);
  luaL_openlibs(g_L);
  lua_gc(g_L,LUA_GCRESTART,0);

  lua_pushstring(g_L,g_luacode);
  lua_setglobal(g_L,"scriptpath");
  lua_pushstring(g_L,basename(g_luacode)); /* Solaris bitches about this line */
  lua_setglobal(g_L,"script");

  lua_register(g_L,"alarm",syslogintr_alarm);
  lua_register(g_L,"host", syslogintr_host);
  lua_register(g_L,"relay",syslogintr_relay);

  /*--------------------------------------------------
  ; this metatable exists so we can call tostring() on
  ; our "host" userdata.
  ;---------------------------------------------------*/
  
  luaL_newmetatable(g_L,LUA_UD_HOST);
  lua_pushliteral(g_L,"__tostring");
  lua_pushcfunction(g_L,syslogintr_ud__toprint);
  lua_settable(g_L,-3);
  lua_pop(g_L,1);
  
  if (g_lpath)
    add_lua_path("path",g_lpath);
  
  if (g_lcpath)
    add_lua_path("cpath",g_lcpath);

  set_signal_handler(SIGINT, handle_signal);
  set_signal_handler(SIGUSR1,handle_signal);
  set_signal_handler(SIGHUP ,handle_signal);
  set_signal_handler(SIGALRM,handle_signal);
  set_signal_handler(SIGTERM,handle_signal);
  
  load_script();
  internal_log(LOG_DEBUG,"PID: %lu",(unsigned long)getpid());
  
  struct pollfd events[g_maxsocket];
  
  for (size_t i = 0 ; i < g_maxsocket ; i++)
  {
    events[i].fd     = g_sockets[i].sock;
    events[i].events = POLLIN;
  }

  while(!mf_sigint)
  {
    assert(lua_gettop(g_L) == 0);
    
    if (mf_sigusr1)
    {
      mf_sigusr1 = 0;
      load_script();
    }

    if (mf_sighup)
    {
      mf_sighup = 0;
      call_optional_luaf("reload_signal");
    }
    
    if (mf_sigalarm)
    {
      mf_sigalarm = 0;
      call_optional_luaf("alarm_handler");
    }
    
    /*--------------------------------------------------------------------
    ; check for any locally queued messages, and pass them all along.  Don't
    ; forget to clean up afterwards.
    ;---------------------------------------------------------------------*/
    
    for (
          struct msg *msg = (struct msg *)ListRemHead(&g_intlog);
          NodeValid(&msg->node);
          msg = (struct msg *)ListRemHead(&g_intlog)
        )
    {
      process_msg(msg);
      assert(msg->raw.text == msg->msg.text);
      free((void *)msg->raw.text);
      free(msg);
    }
    
    /*---------------------------------------------------------------
    ; now check for any requests outside of ourselves
    ;-------------------------------------------------------------*/
    
    if (poll(events,g_maxsocket,-1) < 1)
      continue;	/* continue on errors and timeouts */
    
    for (size_t i = 0 ; i < g_maxsocket; i++)
    {
      if ((events[i].revents & POLLIN))
        event_read(&g_sockets[i]);
    }
  }

  call_optional_luaf("cleanup");  
  lua_close(g_L);
  
  for (size_t i = 0 ; i < g_maxsocket; i++)
  {
    if (g_sockets[i].sock != -1) close(g_sockets[i].sock);
    if (g_sockets[i].local.ss.sa_family == AF_LOCAL)
      unlink(g_sockets[i].local.ssun.sun_path);
  }
  
  unlink(PID_FILE);	/* don't care if this succeeds or not */
  
  /*------------------------------------------------------------------------
  ; Per http://www.cons.org/cracauer/sigint.html, the only proper way to
  ; exit a program that has received a SIGINT (or SIGQUIT) is to actually
  ; use the default action of SIGINT (or SIGQUIT) so that the calling
  ; program can detect that the child process (in this case, us) actually
  ; received a signal.  So that's why we set the default handler for SIGINT
  ; and kill ourselves, since the only way we get here is via SIGINT (or
  ; possibly SIGQUIT if/when I add logic for that).
  ;------------------------------------------------------------------------*/
  
  set_signal_handler(SIGINT,SIG_DFL);
  kill(getpid(),SIGINT);
  
  return EXIT_SUCCESS;	/* keep this around to silence the compilers */
}

/*************************************************************/

Status ipv4_socket(const char *taddr)
{
  assert(taddr != NULL);
  
  if (g_maxsocket == MAX_SOCKETS)
    return retstatus(false,EADDRNOTAVAIL,"ipv4_socket()");
    
  g_ipv4 = g_maxsocket++;
  inet_pton(AF_INET,taddr,&g_sockets[g_ipv4].local.sin.sin_addr.s_addr);
  g_sockets[g_ipv4].local.sin.sin_family = AF_INET;
  g_sockets[g_ipv4].local.sin.sin_port   = htons(LOG_PORT);
  return create_socket(&g_sockets[g_ipv4],sizeof(struct sockaddr_in));
}

/*************************************************************/

Status ipv6_socket(const char *taddr)
{
  assert(taddr != NULL);
  
  if (g_maxsocket == MAX_SOCKETS)
    return retstatus(false,EADDRNOTAVAIL,"ipv6_socket()");
  
  g_ipv6 = g_maxsocket++;
  inet_pton(AF_INET6,taddr,&g_sockets[g_ipv6].local.sin6.sin6_addr.s6_addr);
  g_sockets[g_ipv6].local.sin6.sin6_family = AF_INET6;
  g_sockets[g_ipv6].local.sin6.sin6_port   = htons(LOG_PORT);
  return create_socket(&g_sockets[g_ipv6],sizeof(struct sockaddr_in6));
}

/**************************************************************/

Status local_socket(const char *name)
{
  Status status;
  mode_t oldmask;
  size_t local;
  size_t namelen;
  
  assert(name != NULL);
  
  if (g_maxsocket == MAX_SOCKETS)
    return retstatus(false,EADDRNOTAVAIL,"local_socket()");
    
  local   = g_maxsocket++;  
  oldmask = umask(0111);
  namelen = strlen(name);

  if (namelen > sizeof(struct sockaddr_un) - 1)
    namelen = sizeof(struct sockaddr_un) - 1;
    
  unlink(name);
  memset(&g_sockets[local].local,0,sizeof(struct sockaddr_un));
  memcpy(g_sockets[local].local.ssun.sun_path,name,namelen);
  g_sockets[local].local.ssun.sun_family = AF_LOCAL;
  status = create_socket(&g_sockets[local],sizeof(g_sockets[local].local.ssun));
  umask(oldmask);
  return status;
}

/*******************************************************************/

Status create_socket(SocketNode listen,socklen_t saddr)
{
  int reuse = 1;
  int flag;

  assert(listen != NULL);  
  assert(saddr  >  0);
  
  listen->sock = socket(listen->local.ss.sa_family,SOCK_DGRAM,0);
  
  if (setsockopt(listen->sock,SOL_SOCKET,SO_REUSEADDR,&reuse,sizeof(reuse)) == -1)
    return retstatus(false,errno,"setsockopt(REUSE)");

  flag = fcntl(listen->sock,F_GETFL,0);
  if (flag == -1)
    return retstatus(false,errno,"fcntl(GETFL)");
  
  if (fcntl(listen->sock,F_SETFL,flag | O_NONBLOCK) == -1)
    return retstatus(false,errno,"fcntl(SETFL)");

  if (bind(listen->sock,&listen->local.ss,saddr) == -1)
    return retstatus(false,errno,"bind()");

  /*-------------------------------------------------------------------------
  ; check if any of the addresses passed in are mutlicast addresses, and if
  ; so, notify membership in said multicast group.
  ;------------------------------------------------------------------------*/
  
  if (
       (listen->local.ss.sa_family == AF_INET6) 
       && IN6_IS_ADDR_MULTICAST(&listen->local.sin6.sin6_addr)
     )
  {
    struct ipv6_mreq mreq6;
    
    mreq6.ipv6mr_multiaddr = listen->local.sin6.sin6_addr;
    mreq6.ipv6mr_interface = 0;
    if (setsockopt(listen->sock,IPPROTO_IPV6,IPV6_ADD_MEMBERSHIP,&mreq6,sizeof(mreq6)) < 0)
      return retstatus(false,errno,"setsockopt(MULTICAST6)");
  }
  else if (
            (listen->local.ss.sa_family == AF_INET)
            && IN_MULTICAST(ntohl(listen->local.sin.sin_addr.s_addr))
          )
  {
    struct ip_mreq mreq;
    
    mreq.imr_multiaddr = listen->local.sin.sin_addr;
    mreq.imr_interface.s_addr = INADDR_ANY;
    if (setsockopt(listen->sock,IPPROTO_IP,IP_ADD_MEMBERSHIP,&mreq,sizeof(mreq)) < 0)
      return retstatus(false,errno,"setsockopt(MULTICAST)");
  }
  
  return c_okay;
}
 
/*****************************************************************/  

void event_read(SocketNode sock)
{
  sockaddr_all remote;           
  socklen_t    remsize;
  ssize_t      bytes;
  char         buffer[65536uL]; /* 65507 max size of UDP packet */
  
  assert(sock != NULL);
  
  memset(&remote,0,sizeof(remote));
  remsize = sizeof(remote);
  bytes   = recvfrom(sock->sock,buffer,sizeof(buffer),0,(struct sockaddr *)&remote,&remsize);
  
  if (bytes == -1)
  {
    if (errno == EINTR) return;
    internal_log(LOG_DEBUG,"recvfrom() = %s",strerror(errno));
    return;
  }
  
  assert(bytes         >= 0);
  assert((size_t)bytes < sizeof(buffer));
  
  buffer[bytes] = '\0';
  
  for (size_t i = 0 ; buffer[i] != '\0'; i++)
    if (iscntrl(buffer[i]))
      buffer[i] = ' ';
  
  syslog_interp(&sock->local,&remote,buffer,&buffer[bytes]);
}

/*********************************************************************/

void syslog_interp(sockaddr_all *ploc,sockaddr_all *pss,const char *buffer,const char *end)
{
  struct msg msg;
  char       host[BUFSIZ];
  struct tm  dateread;
  time_t     now;
  int        value;
  char      *p;
  char      *q;
  
  assert(ploc   != NULL);
  assert(pss    != NULL);
  assert(buffer != NULL);
  assert(end    != NULL);
  assert(buffer <= end);
  
  now = time(NULL);
  localtime_r(&now,&dateread);
  
  msg.version       = 0;
  msg.raw.size      = (size_t)(end - buffer);
  msg.raw.text      = buffer;
  msg.timestamp     = now;
  msg.logtimestamp  = now;
  msg.program       = c_null;
  msg.relay         = c_null;
  msg.pid           = 0;
  
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
    msg.host.size = strlen(ploc->ssun.sun_path);
    msg.host.text = ploc->ssun.sun_path;
    msg.port      = -1;
  }
  
  /*----------------------------------------------------------------------
  ; the use of explicit values for LOG_USER and LOG_NOTICE here is because
  ; the values defined are *not* the *direct* values---LOG_USER (in fact,
  ; all the defined facilities) are biased by a multiplier (8---at least on
  ; my system).  Thus, the direct, non-#define'ed values used here.
  ;
  ; Also, if there's any problem parsing the front end of the message, we
  ; log the raw message we received using "user.notice".
  ;---------------------------------------------------------------------*/
  
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
  
  msg.facility  = value / 8;
  msg.level     = value % 8;
  
  /*-------------------------------------------
  ; check to make sure our facility doesn't
  ; exceed what we're expecting
  ;-------------------------------------------*/
  
  if (msg.facility > 23)	/* LOG_LOCAL7 */
  {
    msg.facility = 1;	/* LOG_USER */
    msg.level    = 5;	/* LOG_NOTICE */
    msg.msg      = msg.raw;
    
    process_msg(&msg);
    return;
  }
  
  /*---------------------------------------------
  ; check for a supplied timestamp.
  ;---------------------------------------------*/
  
  q = strptime(p,"%b %d %H:%M:%S",&dateread);
  
  if (q)
  {
    msg.logtimestamp = mktime(&dateread);
    if (*q != ' ')
    {
      msg.facility = 1; /* LOG_USER */
      msg.level    = 5; /* LOG_NOTICE */
      msg.msg      = msg.raw;

      process_msg(&msg);
      return;
    }
    p = q + 1;
  }
  
  /*------------------------------------------------------------------------
  ; check for origin field.  We only look for IPv4/IPv6 literal addresses as
  ; that's the only reliable way to actually transmit such information (and
  ; parse it as intended per RFC3164).  Thus, this code will fail if a
  ; hostname is sent, but it would also fail if the program name with an
  ; embedded space but no host is sent.
  ; 
  ; I suppose I could check to see if the first white-space delimited field
  ; *only* contains alphanumberics, but then it could fail on a message that
  ; is sent that contains neither a host nor a program (which is possible).
  ;
  ; Pick your poison ... this works for me 
  ;-------------------------------------------------------------------------*/

  assert(p <= end);
  q = memchr(p,' ',(size_t)(end - p));
  
  if (q)
  {
    size_t        len = (size_t)(q - p);
    char          addr[len + 1];
    unsigned char addrip[16];	/* big enough */
    int           rc;
    
    memcpy(addr,p,len);
    addr[len] = '\0';
    
    rc = inet_pton(AF_INET6,addr,&addrip);
    if (rc == 1)	/* valid IPv6 address */
    {
      msg.host.text = p;
      msg.host.size = len;
      p = q + 1;
    }
    else
    {
      rc = inet_pton(AF_INET,addr,&addrip);
      if (rc == 1)	/* valid IPv4 address */
      {
        msg.host.text = p;
        msg.host.size = len;
        p = q + 1;
      }
    }
  }

  /*-----------------------------------------------------------------------
  ; check for program field.  Quick and dirty check that works so far.
  ; Basically, we check for the ':' character, which appears to nearly
  ; always terminate this field.  Then we check for the '[', which mostly
  ; (but not always) indicates the PID.  This handles every case I've
  ; encounted so far, with program names with embedded spaces; that and PID
  ; field, what have you.  It doesn't catch *all* PIDs, as there's a program
  ; (gconfd, I'm looking at you) that embed the PID in parenthesis along
  ; with the userid, but hey, if that's *really* important, we can handle it
  ; here.
  ;------------------------------------------------------------------------*/
  
  assert(p <= end);
  q = memchr(p,':',(size_t)(end - p));
  
  if (q)
  {
    char *b;
    
    b = memchr(p,'[',(size_t)(q - p));
    if (b)
      msg.pid = strtoul(b + 1,NULL,10);
    else
      b = q;
      
    msg.program.text = p;
    msg.program.size = (size_t)(b - p);
    
    for (p = q + 1 ; *p && isspace(*p) ; p++)
      ;    
  }

  /*---------------------------------------------------
  ; whatever remains, however small, is the msg.
  ;---------------------------------------------------*/
  
  msg.msg.text = p;
  msg.msg.size = (size_t)(end - p);
  
  process_msg(&msg);
}

/***********************************************************************/

#ifdef CHECK_STRINGS
  static void clean_string(struct sysstring s)
  {
    assert(s.text != NULL);
    
    for (size_t i = 0 ; i < s.size ; i++)
      assert(isprint(s.text[i]));
  }
#endif

/**********************************************************************/

void process_msg(const struct msg *const pmsg)
{
  const char *err;
  int         rc;
  
  assert(pmsg != NULL);

#ifdef CHECK_STRINGS
  clean_string(pmsg->raw);
  clean_string(pmsg->host);
  clean_string(pmsg->relay);
  clean_string(pmsg->program);
  clean_string(pmsg->msg);
#endif

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
  
  lua_pushliteral(g_L,"relay");
  lua_pushlstring(g_L,pmsg->relay.text,pmsg->relay.size);
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
    internal_log(LOG_ERR,"Lua ERROR(%d): %s",rc,err);
    lua_pop(g_L,1);
  }
}

/**********************************************************************/

Status globalv_init(int argc,char *argv[])
{
  static char luascript[FILENAME_MAX];
  Status      status;
  int         option = 0;
  
  assert(argc >  0);
  assert(argv != NULL);
  
  ListInit(&g_intlog);
  g_logtag.text = basename(argv[0]);
  g_logtag.size = strlen(g_logtag.text);
  
  for (size_t i = 0 ; i < MAX_SOCKETS; i++)
    g_sockets[i].sock = -1;

  opterr = 0;	/* prevent getopt_long() from printing error message */
  
  while(true)
  {
    switch(getopt_long(argc,argv,"f46lhu:g:s:p:c:i:I:",c_options,&option))
    {
      default:
      case OPT_ERR:
           fprintf(stderr,"unknown option '%c'\n",optopt);
      case OPT_HELP:
           usage(argv[0]);
           return retstatus(false,0,"");
      case OPT_NONE: 
           break;
      case OPT_FG:
           gf_foreground = 1;
           break;
      case OPT_IPv4:
           status = ipv4_socket(LOG_IPv4);
           if (!status.okay) return status;
           break;
      case OPT_IPv4int:
           status = ipv4_socket(optarg);
           if (!status.okay) return status;
           break;
      case OPT_IPv6:
           status = ipv6_socket(LOG_IPv6);
           if (!status.okay) return status;
           break;
      case OPT_IPv6int:
           status = ipv6_socket(optarg);
           if (!status.okay) return status;
           break;
      case OPT_LOCAL:
           status = local_socket(LOG_LOCAL);
           if (!status.okay) return status;
           break;
      case OPT_SOCKET:
           status = local_socket(optarg);
           if (!status.okay) return status;
           break;
      case OPT_USER:
           g_user = optarg;
           break;
      case OPT_GROUP:
           g_group = optarg;
           break;
      case OPT_PATH:
           g_lpath = optarg;
           break;
      case OPT_CPATH:
           g_lcpath = optarg;
           break;
      case EOF:
           if (optind < argc)
           {
             if (argv[optind][0] == '/')
               g_luacode = argv[optind];
             else
             {
               /*---------------------------------------------------------
               ; this bit is here to turn a relative path into a full path
               ; based upon our current path.  We do this because we change
               ; to the root dirctory when going into daemon mode.  This
               ; way, we won't hang a possible unmount command because we're
               ; in some mounted directory---check comments in daemon_init()
               ; for more details.
               ;----------------------------------------------------------*/
      
               char  cwd[FILENAME_MAX];
               char *path;
      
               path = getcwd(cwd,FILENAME_MAX);
               if (path == NULL)
                 return retstatus(false,errno,"getcwd()");

               snprintf(luascript,FILENAME_MAX,"%s/%s",path,argv[optind]);
               g_luacode = luascript;
             }
           }
           return c_okay;
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
        "\t-4 | --ip                       accept from IPv4 hosts\n"
        "\t   | --ip4                            \"\n"
        "\t   | --ipv4                           \"\n"
        "\t-i | --ipaddr <IPv4addr>        accept IPv4 on IPv4addr\n"
        "\t   | --ip4addr <IPv4addr>             \"\n"
        "\t   | --ipv4addr <IPv4addr>            \"\n"
        "\t-6 | --ip6                      accept from IPv6 hosts\n"
        "\t   | --ipv6                           \"\n"
        "\t-I | --ip6addr <IPv6addr>       accept IPv6 on IPv6 addr\n"
        "\t   | --ipv6addr <IPv6addr>            \"\n"
        "\t-l | --local                    accept from " LOG_LOCAL "\n"
        "\t-s | --socket <path>            accept from unix socket (%d max)\n"
        "\t-f | --foreground               run in foreground\n"
        "\t-u | --user  <username>         user to run as (no default)\n"
        "\t-g | --group <groupname>        group to run as (no default)\n"
        "\t-p | --lua-path <path>          add path to Lua package.path\n"
        "\t-c | --lua-cpath <path>         add path to Lua package.cpath\n"
        "\t-h | --help                     this message\n"
        "\n"
        "\t" LUA_CODE "\tdefault luafile\n"
        "\n",
        progname,
        MAX_SOCKETS - 3		/* possible IPv4, IPv6 and default local */
  );
}

/*******************************************************************/

Status drop_privs(void)
{
  if (g_user == NULL)	/* if no user specified, we won't drop */
    return c_okay;
    
  if (getuid() != 0)	/* if not root, we can't drop privs */
    return c_okay;

  long ubufsize = sysconf(_SC_GETPW_R_SIZE_MAX);
  if (ubufsize < 0) ubufsize = BUFSIZ;
    
  char           ubuffer[ubufsize];
  struct passwd  uinfo;
  struct passwd *uresult;
  
  if (getpwnam_r(g_user,&uinfo,ubuffer,ubufsize,&uresult) != 0)
    return retstatus(false,errno,"getpwnam_r()");
  
  long gbufsize = sysconf(_SC_GETGR_R_SIZE_MAX);
  if (gbufsize < 0) gbufsize = BUFSIZ;
  
  char          gbuffer[gbufsize];
  struct group  ginfo;
  struct group *gresult;
  
  if (g_group == NULL)
  {
    if (getgrnam_r(g_group,&ginfo,gbuffer,gbufsize,&gresult) != 0)
      return retstatus(false,errno,"getgrnam_r()");
  }
  else
    ginfo.gr_gid = uinfo.pw_gid;
  
  /*------------------------------------------------------------------------
  ; it's here we change the ownership of the PID file and any unix sockets. 
  ; I don't care about the return value, as it may not even exist (because
  ; we might not have had perms to create it in the first place.
  ;------------------------------------------------------------------------*/
  
  chown(PID_FILE,uinfo.pw_uid,ginfo.gr_gid);	/* don't care about results */

  for (size_t i = 0 ; i < g_maxsocket ; i++)
    if (g_sockets[i].local.ss.sa_family == AF_LOCAL)
      chown(g_sockets[i].local.ssun.sun_path,uinfo.pw_uid,ginfo.gr_gid);

  /*-------------------------------------------------------------------
  ; change our group id first, then user id.  If we drop user id first,
  ; we may not be able to change our group id!
  ;-------------------------------------------------------------------*/
  
  if (setgid(ginfo.gr_gid) == -1)
    return retstatus(false,errno,"setgid()");
  
  if (setuid(uinfo.pw_uid) == -1)
    return retstatus(false,errno,"getuid()");
  
  internal_log(LOG_DEBUG,"dropped privs to %s:%s",g_user,g_group);
  return c_okay;
}

/*************************************************************************/

void load_script(void)
{
  int rc;
  
  rc = luaL_loadfile(g_L,g_luacode);
  if (rc != 0)
  {
    const char *err = lua_tostring(g_L,1);
    internal_log(LOG_DEBUG,"Lua ERROR: (%d) %s",rc,err);
    lua_pop(g_L,1);
    return;
  }
  
  rc = lua_pcall(g_L,0,LUA_MULTRET,0);
  if (rc != 0)
  {
    const char *err = lua_tostring(g_L,1);
    internal_log(LOG_ERR,"Lua ERROR: (%d) %s",rc,err);
    lua_pop(g_L,1);
    return;
  }
  
  internal_log(LOG_DEBUG,"loaded script %s",g_luacode);
}

/*************************************************************************/

Status daemon_init(void)
{
  pid_t pid;
  int   fh;
  
  /*-----------------------------------------------------------------------
  ; From the Unix Programming FAQ (corraborated by Stevens):
  ;
  ; 1. 'fork()' so the parent can exit, this returns control to the command
  ;    line or shell invoking your program.  This step is required so that
  ;    the new process is guaranteed not to be a process group leader. The
  ;    next step, 'setsid()', fails if you're a process group leader.
  ;---------------------------------------------------------------------*/
             
  pid = fork();
  if (pid == (pid_t)-1)
    return retstatus(false,errno,"fork()");
  else if (pid != 0)	/* parent goes bye bye */
    _exit(EXIT_SUCCESS);
  
  /*-------------------------------------------------------------------------
  ; 2. 'setsid()' to become a process group and session group leader. Since
  ;    a controlling terminal is associated with a session, and this new
  ;    session has not yet acquired a controlling terminal our process now
  ;    has no controlling terminal, which is a Good Thing for daemons.
  ;
  ;    _Advanced Programming in the Unix Environment_, 2nd Edition, also
  ;    ignores SIGHUP.  So adding that here as well.
  ;-----------------------------------------------------------------------*/

  setsid();
  set_signal_handler(SIGHUP,SIG_IGN);	/* ignore this signal for now */

  /*-------------------------------------------------------------------------
  ; 3. 'fork()' again so the parent, (the session group leader), can exit. 
  ;    This means that we, as a non-session group leader, can never regain a
  ;    controlling terminal.
  ;------------------------------------------------------------------------*/

  pid = fork();
  if (pid == (pid_t)-1)
    return retstatus(false,errno,"fork(2)");
  else if (pid != 0)	/* parent goes bye bye */
    _exit(EXIT_SUCCESS);
  
  /*-------------------------------------------------------------------------
  ; 4. 'chdir("/")' to ensure that our process doesn't keep any directory in
  ;    use. Failure to do this could make it so that an administrator
  ;    couldn't unmount a filesystem, because it was our current directory.
  ;
  ;    [Equivalently, we could change to any directory containing files
  ;    important to the daemon's operation.] 
  ;
  ; I just made sure the name of the script we are using contains the full
  ; path.
  ;-------------------------------------------------------------------------*/
            
  chdir("/");
  
  /*-----------------------------------------------------------------------
  ; 5. 'umask(022)' so that we have complete control over the permissions of
  ;    anything we write. We don't know what umask we may have inherited.
  ;-----------------------------------------------------------------------*/

  umask(022);       
  
  /*-----------------------------------------------------------------------
  ; 6. 'close()' fds 0, 1, and 2. This releases the standard in, out, and
  ;    error we inherited from our parent process. We have no way of knowing
  ;    where these fds might have been redirected to. Note that many daemons
  ;    use 'sysconf()' to determine the limit '_SC_OPEN_MAX'. 
  ;    '_SC_OPEN_MAX' tells you the maximun open files/process. Then in a
  ;    loop, the daemon can close all possible file descriptors. You have to
  ;    decide if you need to do this or not.  If you think that there might
  ;    be file-descriptors open you should close them, since there's a limit
  ;    on number of concurrent file descriptors.
  ;
  ; 7. Establish new open descriptors for stdin, stdout and stderr. Even if
  ;    you don't plan to use them, it is still a good idea to have them
  ;    open.  The precise handling of these is a matter of taste; if you
  ;    have a logfile, for example, you might wish to open it as stdout or
  ;    stderr, and open '/dev/null' as stdin; alternatively, you could open
  ;    '/dev/console' as stderr and/or stdout, and '/dev/null' as stdin, or
  ;    any other combination that makes sense for your particular daemon.
  ;
  ; We do this here via dup2(), which combines steps 6 & 7.
  ;------------------------------------------------------------------------*/

  fh = open(DEV_NULL,O_RDWR);
  if (fh == -1)
    return retstatus(false,errno,"open(" DEV_NULL ")");
  
  assert(fh > 2);
  
  dup2(fh,STDIN_FILENO);
  dup2(fh,STDOUT_FILENO);
  dup2(fh,STDERR_FILENO);
  
  close(fh);
  
  return c_okay;
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
    case SIGTERM: mf_sigint   = 1; break;
    case SIGINT:  mf_sigint   = 1; break;
    case SIGUSR1: mf_sigusr1  = 1; break;
    case SIGHUP:  mf_sighup   = 1; break;
    case SIGALRM: mf_sigalarm = 1; break;
    default: break;
  }
}

/**********************************************************************/

Status set_signal_handler(int sig,void (*handler)(int))
{
  struct sigaction act;
  struct sigaction oact;
  
  sigemptyset(&act.sa_mask);
  act.sa_handler = handler;
  act.sa_flags   = 0;
  
  if (sigaction(sig,&act,&oact) == -1)
    return retstatus(false,errno,"sigaction()");
  return c_okay;
}

/**************************************************************************/

int syslogintr_alarm(lua_State *L)
{
  struct itimerval set;
  int              pcount;
  
  assert(L != NULL);
  
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
  else
    return luaL_error(L,"expected number or string");

  internal_log(LOG_DEBUG,"Alarm PID: %lu",(unsigned long)getpid());
  internal_log(LOG_DEBUG,"Alarm set for %d seconds",g_alarm);
  
  set.it_value.tv_sec  = set.it_interval.tv_sec  = g_alarm;
  set.it_value.tv_usec = set.it_interval.tv_usec = 0;
  
  if (setitimer(ITIMER_REAL,&set,NULL) == -1)
    internal_log(LOG_WARNING,"setitimer() = %s",strerror(errno));
  
  lua_pop(L,1);
  return 0;
}

/***********************************************************************/

int syslogintr_ud__toprint(lua_State *L)
{
  sockaddr_all *paddr;
  char          taddr[BUFSIZ];
  const char   *r;
  
  assert(L != NULL);
  
  paddr = luaL_checkudata(L,1,LUA_UD_HOST);
  lua_pop(L,1);
  
  switch(paddr->ss.sa_family)
  {
    case AF_INET:  
         r = inet_ntop(AF_INET, &paddr->sin.sin_addr.s_addr,taddr,BUFSIZ);
         break;
    case AF_INET6: 
         r = inet_ntop(AF_INET6,&paddr->sin6.sin6_addr.s6_addr,taddr,BUFSIZ);
         break;
    default: 
         lua_pushnil(L);
         return 1;
  }
  
  if (r == NULL)
    lua_pushliteral(L,"");
  else
    lua_pushstring(L,taddr);

  return 1;
}

/*********************************************************************/

int syslogintr_host(lua_State *L)
{
  const char      *hostname;
  struct addrinfo  hints;
  struct addrinfo *results;
  sockaddr_all    *paddr;
  size_t           size;
  int              rc;
  
  assert(L != NULL);
  
  hostname = luaL_checkstring(L,1);
  lua_pop(L,1);
  
  memset(&hints,0,sizeof(hints));
  hints.ai_flags    = AI_NUMERICSERV;
  hints.ai_family   = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;
  
  rc = getaddrinfo(hostname,"514",&hints,&results);
  if (rc != 0)
  {
    internal_log(LOG_WARNING,"getaddrinfo(%s) = %s",hostname,strerror(errno));
    lua_pushnil(L);
    return 1;
  }
  
  switch(results[0].ai_addr->sa_family)
  {
    case AF_INET:  size = sizeof(struct sockaddr_in);  break;
    case AF_INET6: size = sizeof(struct sockaddr_in6); break;
    default: 
         internal_log(LOG_WARNING,"unexpected family for address");
         freeaddrinfo(results);
         lua_pushnil(L);
         return 1;
  }
    
  paddr = lua_newuserdata(L,size);
  luaL_getmetatable(L,LUA_UD_HOST);
  lua_setmetatable(L,-2);
  memcpy(paddr,results[0].ai_addr,size);
  freeaddrinfo(results);
  return 1;
}

/************************************************************************/

int syslogintr_relay(lua_State *L)
{
  sockaddr_all *paddr;
  struct msg    msg;
  struct tm     stm;
  char          date  [BUFSIZ];
  char          output[BUFSIZ];
  char         *p;
  size_t        max;
  size_t        size;
  size_t        dummy;
  
  assert(L != NULL);
  
  paddr = luaL_checkudata(L,1,LUA_UD_HOST);
  luaL_checktype(L,2,LUA_TTABLE);
  
  lua_getfield(L,2,"version");
  lua_getfield(L,2,"remote");
  lua_getfield(L,2,"host");
  lua_getfield(L,2,"logtimestamp");
  lua_getfield(L,2,"program");
  lua_getfield(L,2,"pid");
  lua_getfield(L,2,"facility");
  lua_getfield(L,2,"level");
  lua_getfield(L,2,"msg");
  
  msg.version      = lua_tointeger(L,-9);
  msg.remote       = lua_toboolean(L,-8);
  msg.host.text    = lua_tolstring(L,-7,&msg.host.size);
  msg.logtimestamp = lua_tointeger(L,-6);
  msg.program.text = lua_tolstring(L,-5,&msg.program.size);
  msg.pid          = lua_tointeger(L,-4);
  msg.facility     = map_str_to_int(lua_tolstring(L,-3,&dummy),c_facility,MAX_FACILITY);
  msg.level        = map_str_to_int(lua_tolstring(L,-2,&dummy),c_level,   MAX_LEVEL);
  msg.msg.text     = lua_tolstring(L,-1,&msg.msg.size);
  
  localtime_r(&msg.logtimestamp,&stm);
  strftime(date,BUFSIZ,"%b %d %H:%M:%S",&stm);

  p   = output;
  max = BUFSIZ;
  
  size = snprintf(p,max,"<%d>%s ",msg.facility * 8 + msg.level,date);
  max -= size;
  p   += size;
  
  if (msg.remote)
  {
    assert(msg.host.size > 0);    
    size = snprintf(p,max,"%s ",msg.host.text);
    max -= size;
    p   += size;
  }
  
  if (msg.program.size)
  {
    if (msg.pid)
      size = snprintf(p,max,"%s[%d]",msg.program.text,msg.pid);
    else
      size = snprintf(p,max,"%s",msg.program.text);
    max -= size;
    p   += size;
  }
  
  size = snprintf(p,max,": %s",msg.msg.text);
  size = (size_t)((p + size) - output);

  if (size > MAX_MSGLEN)
  {
    size = MAX_MSGLEN;
    output[size] = '\0';
  }
  
  if ((paddr->ss.sa_family == AF_INET) && (g_sockets[g_ipv4].sock > -1))
  {
    assert(g_sockets[g_ipv4].local.sin.sin_family == AF_INET);
    if (sendto(g_sockets[g_ipv4].sock,output,size,0,&paddr->ss,sizeof(struct sockaddr_in)) == -1)
      internal_log(LOG_ERR,"sendto(ipv4) = %s",strerror(errno));
  }
  else if ((paddr->ss.sa_family == AF_INET6) && (g_sockets[g_ipv6].sock > -1))
  {
    assert(g_sockets[g_ipv6].local.sin6.sin6_family == AF_INET6);
    if (sendto(g_sockets[g_ipv6].sock,output,size,0,&paddr->ss,sizeof(struct sockaddr_in6)) == -1)
      internal_log(LOG_ERR,"sendto(ipv6) = %s",strerror(errno));
  }
  else
    internal_log(LOG_ERR,"can't relay---improper socket type");

  /*----------------------------------------------------------------
  ; pop after we've used the data from Lua.  Since Lua does
  ; garbage collection, if we pop the parameters before we
  ; use any string data, it may be collected and bad things
  ; would result.
  ;--------------------------------------------------------------*/
  
  lua_pop(L,11);	/* 2 input, 9 fetches */
  return 0;
}

/************************************************************************/

void call_optional_luaf(const char *fname)
{
  lua_getglobal(g_L,fname);
  if (lua_isfunction(g_L,-1))
  {
    int rc = lua_pcall(g_L,0,0,0);
    if (rc != 0)
    {
      const char *err = lua_tostring(g_L,1);
      internal_log(LOG_ERR,"Lua ERROR: (%d) %s",rc,err);
      lua_pop(g_L,1);
    }
  }
  else if (!lua_isnil(g_L,-1))
  {
    internal_log(LOG_WARNING,"%s is type '%s' not type 'function'",fname,lua_typename(g_L,lua_type(g_L,1)));
    lua_pop(g_L,1);
  }
}

/**********************************************************************/

void internal_log(int priority,const char *format, ... )
{
  va_list     args;
  char       *buffer;
  struct msg *msg;
  int         size;
  
  assert(priority >  -1);	/* min priority is 0	*/
  assert(priority <   8);	/* max priority level	*/
  assert(format   != NULL);
  
  buffer = malloc(BUFSIZ);
  if (buffer == NULL)
    return;
    
  msg = malloc(sizeof(struct msg));
  if (msg == NULL)
  {
    free(buffer);
    return;
  }
  
  va_start(args,format);
  size = vsnprintf(buffer,BUFSIZ,format,args);
  va_end(args);
  
  msg->version      = 0;
  msg->raw.size     = size;
  msg->raw.text     = buffer;
  msg->timestamp    = time(NULL);
  msg->logtimestamp = msg->timestamp;
  msg->program      = g_logtag;
  msg->relay        = c_null;
  msg->pid          = 0;
  msg->remote       = false;
  msg->host.text    = "(internal)";
  msg->host.size    = 10; /* yeah, I know ... */
  msg->port         = -1;
  msg->facility     =  5; /* LOG_SYSLOG --- see comment in syslog_interp() */
  msg->level        = priority;
  msg->msg.text     = buffer;
  msg->msg.size     = size;
  
  ListAddTail(&g_intlog,&msg->node);
}

/*************************************************************************/

Node *ListRemHead(List *const pl)
{
  Node *pn;
  
  assert(pl != NULL);
  
  pn = ListGetHead(pl);
  assert(pn != NULL);
  if (NodeValid(pn))
    NodeRemove(pn);
  return pn;
}

/*************************************************************************/

void NodeInsert(Node *const pn,Node *const pntoa)
{
  Node *pnn;
  
  assert(pn    != NULL);
  assert(pntoa != NULL);
  
  pnn            = pn->ln_Succ;
  pntoa->ln_Succ = pnn;
  pntoa->ln_Pred = pn;
  pn->ln_Succ    = pntoa;
  pnn->ln_Pred   = pntoa;
}

/************************************************************************/

void NodeRemove(Node *const pn)
{
  Node *pns;
  Node *pnp;
  
  assert(pn != NULL);
  assert(pn->ln_Succ != NULL);
  assert(pn->ln_Pred != NULL);
  
  pns = pn->ln_Succ;
  pnp = pn->ln_Pred;
  
  pns->ln_Pred = pnp;
  pnp->ln_Succ = pns;
}

/************************************************************************/

void add_lua_path(const char *name,const char *path)
{
  const char *currentpath;
  
  assert(name != NULL);
  assert(path != NULL);
  
  lua_getglobal(g_L,"package");
  lua_getfield(g_L,1,name);
  currentpath = lua_tostring(g_L,-1);
  lua_pop(g_L,1);
  
  lua_pushfstring(g_L,"%s;%s",path,currentpath);
  lua_setfield(g_L,1,name);
  lua_pop(g_L,1);
}

/*************************************************************************/
