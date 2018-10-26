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
#include <lualib.h>

/*************************************************************************/

static int                   m_width;
static int                   m_height;
static int                   mf_tty;
static volatile sig_atomic_t mf_sigwinch;

/**************************************************************************/

static void handler_sigwinch(int sig)
{
  assert(sig == SIGWINCH);
  mf_sigwinch = 1;
}

/**************************************************************************/

static int colortty(lua_State *L)
{
  const char *txt;
  size_t      len;
  size_t      cnt;
  size_t      size;
  
  if (mf_sigwinch && mf_tty)
  {
    struct winsize size;
    
    if (ioctl(STDOUT_FILENO,TIOCGWINSZ,&size) == 0)
    {
      m_width  = size.ws_col;
      m_height = size.ws_row;
    }
    mf_sigwinch = 0;
  }
  
  txt = luaL_checklstring(L,1,&size);
  len = 0;
  cnt = 0;
  
  char buffer[size + 1];
  
  while(*txt)
  {
    if (*txt == '\n')
      cnt = 0;
      
    if (cnt == (unsigned)m_width)
    {
      txt++;
      continue;
    }
    
    if (*txt == 0x1B)
    {
      buffer[len++] = *txt++;
      if (*txt == '[')
      {
        buffer[len++] = *txt++;
        while(*txt < '@')
          buffer[len++] = *txt++;
      }
      else if (*txt == '(')
        buffer[len++] = *txt++;
        
      buffer[len++] = *txt++;
      continue;
    }
    
    if ((unsigned char)*txt == 0x9B)
    {
      buffer[len++] = *txt++;
      while(*txt < '@')
        buffer[len++] = *txt++;
      buffer[len++] = *txt++;
      continue;
    }
    
    cnt++;
    buffer[len++] = *txt++;
  }
  
  buffer[len] = '\0';
  lua_pushlstring(L,buffer,len);
  return 1;
}

/**************************************************************************/

int luaopen_colortty(lua_State *L)
{
  struct winsize   size;
  struct sigaction act;
  struct sigaction oact;
  
  if (!isatty(STDOUT_FILENO))
  {
    mf_tty   = 0;
    m_width  = INT_MAX;
    m_height = INT_MAX;
  }
  else if (ioctl(STDOUT_FILENO,TIOCGWINSZ,&size) == 0)
  {
    mf_tty   = 1;
    m_width  = size.ws_col;
    m_height = size.ws_row;
    sigemptyset(&act.sa_mask);
    act.sa_handler = handler_sigwinch;
    act.sa_flags   = SA_RESTART;
    if (sigaction(SIGWINCH,&act,&oact) < 0)
      return luaL_error(L,"sigaction() = %s",strerror(errno));
  }
  else
  {
    mf_tty   = 0;
    m_width  = 80;
    m_height = 24;
  }
  
  lua_register(L,"colortty",colortty);
  return 0;
}

/**************************************************************************/
