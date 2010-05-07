-- ***************************************************************
--
-- Copyright 2010 by Sean Conner.  All Rights Reserved.
-- 
-- This program is free software; you can redistribute it and/or
-- modify it under the terms of the GNU General Public License
-- as published by the Free Software Foundation; either version 2
-- of the License, or (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, write to the Free Software
-- Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
--
-- Comments, questions and criticisms can be sent to: sean@conman.org
--
-- ********************************************************************
--
-- This program is meant to be run in real time to view logs as they come
-- in.  The primary syslogintr on the network relays the logs to a multicast
-- address, so any client on the segment can get the logs.  This script can
-- then be used to listen on that multicast address and print the logs as
-- they are received.
--
-- One syslogintr on the network does a relay(239.255.0.1,msg) 
-- I run another syslogintr on the network:
--
-- syslogintr --ipaddr 239.255.0.1 --foreground realtime.lua | less -S
-- 	or
-- syslogintr --ipaddr 239.255.0.1 --foreground realtime.lua | cut -b 1-width
--
-- Makes for a pretty display.
--
-- *********************************************************************

-- cut -b 1-187 (to account for XTERM escape sequences)
--io.stdout:write("\27[2J")	-- clear screen to black
--io.stdout:flush()

--[[
if logfiles == nil then
  logfiles = {}
  logfiles = setmetatable({},{
  	__index = function(t,k)
  	  local fname = "/tmp/logs/" .. k
  	  t[k] = io.open(fname,"a")
  	  return t[k]
  	end
  	})
end
--]]

colors =
{
  emerg  = "\27[1;31m",
  alert  = "\27[0;31m",
  crit   = "\27[0;31m",
  err    = "\27[0;31m",
  warn   = "\27[0;33m",
  notice = "\27[1;32m",
  info   = "\27[0;32m",
  debug  = "\27[1;34m"
}

function log(msg)
  io.stdout:write(string.format(
	"%s%15.15s %-15.15s %-6s %6s %s %s\n",
	colors[msg.level],
	msg.host,
	msg.program,
	msg.facility,
	msg.level,
	"|", -- os.date("%b %d %H:%M:%S",msg.timestamp),
	msg.msg
	))
  io.stdout:flush()
  
  --logfiles[msg.host]:write(string.format("%s\n",msg._RAW))
  --logfiles[msg.host]:flush()
end
