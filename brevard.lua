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
-- ***************************************************************************
--
-- This file is the one I'm using on my private server.  Several years ago I
-- diverted from the RedHat standard syslog files to my own, and I kept that
-- system here.  I also direct the logs to my home system so I can monitor
-- the logs in real time (see realtime.lua).
--
-- I also convert several thin Postfix logs to one fat log (summary).
--
-- This configuration is pretty straight forward.
--
-- ***************************************************************************
-- luacheck: ignore 611
-- luacheck: globals alarm host relay script
-- luacheck: globals alarm_handler log cleanup reload_signal logfile

local I_log               = require "I_log"
local postfix_mailsummary = require "postfix-mailsummary"

local homebase = host("127.0.0.1")

-- **********************************************************************

local function log_to_file(file,msg)
  file:write(string.format(
        "%s\t%s\t%s\t%s\t%s\t%s\n",
        os.date("%b %d %H:%M:%S",msg.timestamp),
        msg.facility,
        msg.level,
        msg.host,
        msg.program,
        msg.msg
  ))
  file:flush()
end

-- ******************************************************************

function cleanup()
  logfile:close()
end

-- *********************************************************************

function log(msg)
  if msg.level ~= 'debug' then
    log_to_file(logfile,msg)
  end
  
  if postfix_mailsummary(msg) then
    log_to_file(logfile,msg)
    msg.remote = true
    msg.host   = "66.252.224.242"
    relay(homebase,msg)
  end
end

-- **************************************************************

function reload_signal()
  if logfile ~= nil then
    logfile:close()
  end
  
  logfile = io.open("/var/log/syslog","a")
  I_log("info","signal received loud and clear; reset logfiles")
end

-- *************************************************************

if logfile == nil then
  logfile = io.open("/var/log/syslog","a")
end

I_log("info","reloaded script")
I_log("debug",string.format("relaying to %s",tostring(homebase)))
