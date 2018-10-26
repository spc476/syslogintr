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

/*******************************************************************
*
* loadavg       - retrieve the system load for a Unix system
*                 It returns three values
*
*******************************************************************/

#define _BSD_SOURCE

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

/**************************************************************************/

static int la_loadavg(lua_State *L)
{
  double load[3];
  
  if (getloadavg(load,3) == -1)
    return luaL_error(L,"getloadavg() = %s",strerror(errno));
    
  lua_pushnumber(L,load[0]);
  lua_pushnumber(L,load[1]);
  lua_pushnumber(L,load[2]);
  
  return 3;
}

/*************************************************************************/

int luaopen_loadavg(lua_State *L)
{
  lua_register(L,"loadavg",la_loadavg);
  return 0;
}

/**************************************************************************/
