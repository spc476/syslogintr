/*********************************************************************
*
* Copyright 2010 by Sean Conner.  All Rights Reserved.
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
* Comments, questions and criticisms can be sent to: sean@conman.org
*
*********************************************************************/

/********************************************************************
*
* colortty    - provide a way to cut strings with the width of the current
*               window, taking into account any escape sequences (like
*               changing the color of the text), from lua.  It is written
*               with the assumption that only one line of text is to be
*               written, and long lines may have any trailing '\n' chopped
*               off, so plan accordingly.
*
*               It is called as followed:
*
*                       require "colortty"
*                       print(colortty("a really long line of text"))
*
**********************************************************************/

#ifdef __linux__
#  define _GNU_SOURCE
#endif

#include <string.h>
#include <limits.h>
#include <ctype.h>
#include <errno.h>
#include <assert.h>

#include <sys/ioctl.h>
#include <unistd.h>
#include <termios.h>
#include <signal.h>

#include <lua.h>
#include <lauxlib.h>

/*************************************************************************/

static int                   m_width;
static int                   m_height;
static volatile sig_atomic_t mf_sigwinch;

/**************************************************************************/

static void handler_sigwinch(int sig)
{
  mf_sigwinch = sig;
}

/**************************************************************************/

static int colortty(lua_State *L)
{
  const char *txt = luaL_checkstring(L,1);
  luaL_Buffer buf;
  int         cnt = 0;
  
  if (mf_sigwinch)
  {
    struct winsize size;
    
    if (ioctl(STDOUT_FILENO,TIOCGWINSZ,&size) == 0)
    {
      m_width  = size.ws_col;
      m_height = size.ws_row;
    }
    mf_sigwinch = 0;
  }
  
  luaL_buffinit(L,&buf);
  
  while(*txt)
  {
    if (cnt == m_width)
      break;
    else if (*txt == '\n')
      break;
    else if (*txt == 0x1B)
    {
      luaL_addchar(&buf,*txt++);
      if (*txt == '[')
      {
        luaL_addchar(&buf,*txt++);
        while (*txt < '@')
          luaL_addchar(&buf,*txt++);
      }
      else if (*txt == '(')
        luaL_addchar(&buf,*txt++);
        
      luaL_addchar(&buf,*txt++);
    }
    else if ((unsigned char)*txt == 0x9B)
    {
      luaL_addchar(&buf,*txt++);
      while (*txt < '@')
        luaL_addchar(&buf,*txt++);
      luaL_addchar(&buf,*txt++);
    }
    else
    {
      cnt++;
      luaL_addchar(&buf,*txt++);
    }
  }
  
  luaL_addchar(&buf,'\n');
  luaL_pushresult(&buf);
  return 1;
}

/**************************************************************************/

int luaopen_colortty(lua_State *L)
{
  struct winsize   size;
  struct sigaction act;
  
  if (!isatty(STDOUT_FILENO))
  {
    m_width  = INT_MAX;
    m_height = INT_MAX;
  }
  else if (ioctl(STDOUT_FILENO,TIOCGWINSZ,&size) == 0)
  {
    m_width  = size.ws_col;
    m_height = size.ws_row;
    
    sigemptyset(&act.sa_mask);
    act.sa_handler = handler_sigwinch;
    act.sa_flags   = SA_RESTART;
    
    if (sigaction(SIGWINCH,&act,NULL) < 0)
      return luaL_error(L,"sigaction() = %s",strerror(errno));
  }
  else
  {
    m_width  = 80;
    m_height = 24;
  }
  
  lua_pushcfunction(L,colortty);
  return 1;
}

/**************************************************************************/
