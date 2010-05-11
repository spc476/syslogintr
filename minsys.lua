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
-- For the function called for each request, msg is a table
-- with the following fields:
-- 
-- 	version		integer = 0
-- 	facility	string
-- 	level		string
-- 	timestamp	as from os.time()
-- 	logtimestamp	as from os.time() [1]
-- 	pid		integer (0 if not available) [2]
-- 	program		string  ("" if not available) [3]
-- 	msg		string
-- 	remote		boolean (true if from network socket)
-- 	host		string [4]
--     relay           string  ("" if not available) [6]
-- 	port		integer (-1 if not available) [5]
-- 
-- 	[1]	if the incoming syslog request has a timestamp, this
-- 		will contain it, otherwise it's equal to the timestamp
-- 		field
-- 
-- 	[2]	if the incoming syslog request has a pid field
-- 
-- 	[3]	if the incoming syslog request has a program field
-- 
-- 	[4]	IP address (v4 or v6) of the request.  If it's from
-- 		the local socket (defaults to "/dev/log" under Linux)
-- 		this will be the filename of the localsocket.
-- 
-- 	[5]	Remote port of the request, or -1 if from a localsocket.
-- 
--  	[6]	The message is being relayed from an original source.  If
-- 		that is the case, then host will be set to the original
-- 		source, and relay will be set to the device that sent us the
-- 		message.  If the device was the original sender, then relay
-- 		will be "".
-- 
-- Two variables are also defined:
-- 
-- 	1. scriptpath	- full path of the script
-- 	2. script	- just the script name
-- 
-- ****************************************************************

function log(msg)
  local pid
  
  if msg.pid == 0 then
    pid = ""
  else
    pid = string.format("[%d]",msg.pid)
  end
  
  io.stdout:write(string.format(
  		"%s %s %s%s: %s\n",
  		os.date("%b %d %H:%M:%S",msg.timestamp),
  		msg.host,
  		msg.program,
  		pid,
  		msg.msg
  	))
  io.stdout:flush()
end

-- ***************************************************************
-- * function called when the daemon receives SIGHUP.  There are
-- * no paramters given, nor are any expected from it.
-- ***************************************************************

function reload_signal()
  log{
  	host      = "(internal)",
  	program   = script	-- "script" contains the script name
  	facility  = "syslog",
  	level     = "debug",
  	timestamp = os.time(),
  	msg       = "received signal"
  }
end

-- ****************************************************************
-- * function called every N seconds, set with alarm(N).  There are
-- * no paramters given, nor are any expected from it.
-- *
-- * The alarm() function takes as a paramter, either a number, which
-- * is taken as a number of seconds, or a string, in the format
-- * of "<number><specifier>" where
-- *
-- *	<number>	an integral number
-- *	<specifier>	's' (seconds)
-- *			'm' (minutes)
-- *			'h' (hours)
-- *			'd' (days)
-- *
-- ****************************************************************

-- alarm("1h")		-- set the alarm to go off every hour

function alarm_handler()
  log{
  	host      = "(internal)",
  	program	  = script,
  	facility  = "syslog",
  	level     = "debug",
  	timestamp = os.time(),
  	msg       = "Alarm clock rang---hitting the snooze button"
  }
end

-- *****************************************************************
-- * function called when program is exiting. 
-- *****************************************************************

function cleanup()
  log{
  	host      = "(internal)",
  	program   = script,
  	facility  = "syslog",
  	level     = "debug",
  	timestamp = os.time(),
  	msg       = "Clean up!  We're going away!"
  }
end
