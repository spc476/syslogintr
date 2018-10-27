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
-- This is one (of two) scripts I run at home.  This is the primary script
-- that blocks repeated SSH attempts and also relays all the logs to a
-- multicast address.  The other script I run is realtime.lua (another
-- instance of syslogintr) so that I can view the logs in realtime.
--
-- ************************************************************************
-- luacheck: ignore 611
-- luacheck: globals alarm host relay script
-- luacheck: globals logfile alarm_handler log reload_signal cleanup

local I_log      = require "I_log"
local hostcounts = require "hostcounts"
local ssh        = require "ssh-iptables"

if logfile == nil then
  logfile = io.open("/var/log/syslog","a") or io.stdout
end

alarm("60m")

local logger = host("239.255.0.1")

-- *******************************************************

local function log_to_file(file,msg)
  if msg.program == nil then
    I_log("err","bad parse: " .. msg._RAW)
    return
  end
  
  file:write(string.format(
        "%s\t%s\t%s\t%s\t%s\t%s\n",
        os.date("%b %d %H:%M:%S",msg.timestamp),
        msg.facility,
        msg.level,
        msg.host,
        msg.program,
        msg.msg
  ))
  --file:flush()
end

-- ********************************************************

function reload_signal()

  if logfile ~= io.stdout then
    logfile:close()
    logfile = io.open("/var/log/syslog","a") or io.stdout
  end
  
  hostcounts.log()
  I_log("debug","signal received loud and clear and reset logfile")
  
end

-- *******************************************************

function alarm_handler()
  I_log("debug","Alarm clock");
  hostcounts.log()
  ssh.remove()
end

-- ******************************************************

function log(msg)

  -- ====================================================
  -- My mac is including the hostname in the program portion
  -- (or at least, that's how I'm parsing it).  Strip out the
  -- hostname from anything sent by the Mac
  -- ====================================================
  
  if msg.host == '192.168.1.13' then
    if msg.program:match('^marvin.') then
      msg.program = msg.program:match('^marvin.(.*)')
    end
  end
  
  -- ====================================================
  -- Bunny's machine is sending the hostname, which is
  -- being interpreted as a program name.  This corrects
  -- for that.
  -- ====================================================
  
  if msg.host == '192.168.1.16'
  or msg.host == 'fc00::3'
  then
    local program = string.match(msg.program,'^.*%s+(.*)')
    if program ~= nil then
      msg.program = program
    end
  end
  
  -- =====================================================
  -- Fix my router's message.  msg.program is actually
  -- part of the messsage, not the program.
  -- =====================================================
  
  if msg.host == '192.168.1.1' then
    msg.msg = msg.program .. ": " .. msg.msg
    msg.program = ""
  end
  
  -- =====================================================
  -- I need the PID from the UPS drivers, so check for that
  -- and add to the msg
  -- =====================================================
  
  if msg.program == 'usbhid-ups' then
    msg.msg = string.format("pid = %d , %s",msg.pid,msg.msg)
  end
  
  -- ====================================================
  -- skip logging anything from program 'com.apple.usbmuxd'
  -- but do relay it ...
  -- ====================================================
  
  if msg.program == 'com.apple.usbmuxd' then
    relay(logger,msg)
    return
  end
  
  -- ====================================================
  -- fix nagios logging messages
  -- ====================================================
  
  if msg.program == 'nagios' then
    if msg.msg:match("Warning:") then
      msg.level = 'warn'
    elseif msg.msg:match(" ALERT:") then
      msg.level = 'err'
    end
  end
  
  hostcounts.inc(msg.host)
  log_to_file(logfile,msg)
  ssh.log(msg)
  relay(logger,msg)
end

-- ********************************************************

function cleanup()
  I_log("debug","shutting down ... ")
  ssh.cleanup()
  logfile:close()
end

-- *******************************************************

I_log("debug","path:  " .. package.path)
I_log("debug","reloaded " .. script)
hostcounts.log()
I_log("debug","relaying to " .. tostring(logger))
