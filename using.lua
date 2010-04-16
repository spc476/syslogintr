-- ***************************************************************
--
-- Copyright 2009 by Sean Conner.  All Rights Reserved.
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
-- Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
--
-- Comments, questions and criticisms can be sent to: sean@conman.org
--
-- ********************************************************************

if false then
  package.path = "/home/spc/source/sysloginter/modules/?.lua;" .. package.path
end

require "I_log"
require "hostcounts"

if true then
  require "ssh-iptables"
else
  function sshd(msg)	  end
  function sshd_remove()  end
  function sshd_cleanup() end
end

I_log("debug",package.path)

if logfile == nil then
  logfile = io.open("/var/log/syslog","a") or io.stdout
end

if remotehosts == nil then
  remotehosts = {}
  setmetatable(remotehosts,{ __index = function(t,k) return 0 end })
end

alarm("60m")

-- *******************************************************

function log_remotehosts()
  local s = ""
  
  for name,value in pairs(remotehosts) do
    s = s .. string.format("%s:%d ",name,value)
    remotehosts[name] = 0
  end
  
  log{
  	host      = "(internal)",
  	remote    = false,
  	program   = "summary/hosts",
  	facility  = "syslog",
  	level     = "info",
  	timestamp = os.time(),
  	msg       = s
  }
end

-- *******************************************************

function reload_signal()

  if logfile ~= io.stdout then
    logfile:close()
    logfile = io.open("/var/log/syslog","a") or io.stdout
  end

  log_remotehosts()  
  I_log("debug","signal received loud and clear and reset logfile")

end

-- *******************************************************

function alarm_handler()
  log_remotehosts()  
  I_log("debug","Alarm clock");
  sshd_remove()
end

-- ******************************************************

function log(msg)

  -- ====================================================
  -- Bunny's machine is sending the hostname, which is
  -- being interpreted as a program name.  This corrects
  -- for that.
  -- ====================================================
  
  if msg.host == '192.168.1.16' then
    msg.program = string.match(msg.program,'^.*%s+(.*)')
  end

  remotehosts[msg.host] = remotehosts[msg.host] + 1
  
  log_to_file(logfile,msg)
  sshd(msg)
end

-- ********************************************************

function cleanup()
  sshd_cleanup()
  logfile:close()
end

-- *******************************************************

function log_to_file(file,msg)
  file:write(string.format(
  		"%15.15s | %-15.15s | %-6s %6s | %s | %s\n",
  		msg.host,
  		msg.program,
  		msg.facility,
  		msg.level,
  		os.date("%b %d %H:%M:%S",msg.timestamp),
  		msg.msg
  	))
  file:flush()
end

-- ********************************************************

I_log("debug","reloaded " .. script)
log_remotehosts()

