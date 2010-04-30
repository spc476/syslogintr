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

require "I_log"
require "hostcounts"
require "ssh-iptables"

if logfile == nil then
  logfile = io.open("/var/log/syslog","a") or io.stdout
end

alarm("60m")

logger = host("239.255.0.1")

-- *******************************************************

function reload_signal()

  if logfile ~= io.stdout then
    logfile:close()
    logfile = io.open("/var/log/syslog","a") or io.stdout
  end

  log_hostcounts()  
  I_log("debug","signal received loud and clear and reset logfile")

end

-- *******************************************************

function alarm_handler()
  I_log("debug","Alarm clock");
  log_hostcounts()
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
  
  -- =====================================================
  -- I need the PID from the UPS drivers, so check for that
  -- and add to the msg
  -- =====================================================
  
  if msg.program == 'usbhid-ups' then
    msg.msg = string.format("pid = %d , %s",msg.pid,msg.msg)
  end

  inc_hostcount(msg.host)  
  log_to_file(logfile,msg)
  sshd(msg)
  relay(logger,msg)
end

-- ********************************************************

function cleanup()
  I_log("debug","shutting down ... ")
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
  --file:flush()
end

-- ********************************************************

I_log("debug","path:  " .. package.path)
I_log("debug","reloaded " .. script)
log_hostcounts()
I_log("debug","relaying to " .. tostring(logger))
