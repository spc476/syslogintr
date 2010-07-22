-- ***************************************************************
--
-- Copyright 2010 by Sean Conner.  All Rights Reserved.
-- 
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
-- syslogintr --ipaddr 239.255.0.1 --foreground realtime.lua 
--
-- Makes for a pretty display.
--
-- *********************************************************************

require "colortty"

colors =
{
  emerg  = "\27[1;31m",
  alert  = "\27[0;31m",
  crit   = "\27[0;31m",
  err    = "\27[0;31m",
  warn   = "\27[1;33m",
  notice = "\27[1;32m",
  info   = "\27[0;32m",
  debug  = "\27[1;34m"
}

function log(msg)
  io.stdout:write(colortty(string.format(
  	"%s%15.15s \27[1;39m|%s %s",
  	colors[msg.level],
  	msg.host,
  	colors[msg.level],
  	msg._RAW
  )))
  io.stdout:write("\n")
  io.stdout:flush()
end
