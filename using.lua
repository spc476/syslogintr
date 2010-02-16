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

if blocked == nil then
  blocked = {}
  os.execute("iptables --table filter -F INPUT")
end

if logfile == nil then
  logfile = io.open("/var/log/syslog","a") or io.stdout
end

alarm("60m")

-- *******************************************************

function reload_signal()
  if logfile ~= io.stdout then
    logfile:close()
    logfile = io.open("/var/log/syslog","a") or io.stdout
  end
  
  I_log("debug","signal received loud and clear and reset logfile")
end

-- *******************************************************

function alarm_handler()
  I_log("debug","Alarm clock");
  if #blocked == 0 then
    I_log("debug","Alarm clock---snooze button!")
    return
  end

  local now = os.time()

  I_log("debug",string.format("About to remove blocks (%d left)",#blocked))

  while #blocked > 0 do
    if now - blocked[1].when < 3600 then return end
    local ip = blocked[1].ip
    I_log("info","Removing IP block: " .. ip)      	
    blocked[ip] = nil
    table.remove(blocked,1)
    os.execute("iptables --table filter -D INPUT 1")
  end
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

 writelog(msg)
  sshd(msg)
end

-- ********************************************************

function cleanup()
  for i = 1 , #blocked do
    os.execute("iptables --table filter -D INPUT 1")
  end
  blocked = {}
  logfile:close()
end

-- *******************************************************

function writelog(msg)
  log_to_file(logfile,msg)
end

-- ******************************************************

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

function sshd(msg)
  if msg.remote   == true    then return end
  if msg.program  ~= "sshd"  then return end
  if msg.facility ~= "auth2" then return end
  if msg.level    ~= "info"  then return end

  local ip = string.match(msg.msg,"^Failed password for .* from ::ffff:([%d%.]+) .*");
  if ip == nil then return end

  I_log("debug","Found IP:" .. ip)

  if blocked[ip] == nil then
    blocked[ip] = 1
  else
    blocked[ip] = blocked[ip] + 1
  end

  if blocked[ip] == 5 then
    local cmd = "iptables --table filter --append INPUT --source " .. ip .. " --proto tcp --dport 22 --jump REJECT"
    I_log("debug","Command to block: " .. cmd)    
    os.execute(cmd)    
    I_log("info","Blocked " .. ip .. " from SSH")
    table.insert(blocked,{ ip = ip , when = msg.timestamp} )
  end
end

-- *******************************************************

function I_log(level,msg)
  log{
  	host      = "(internal)",
  	remote    = false,
  	program   = script,
  	facility  = "syslog",
  	level     = level,
  	timestamp = os.time(),
  	msg       = msg
  }
end

-- ******************************************************

I_log("debug","reloaded " .. script)
I_log("debug",string.format("IPs currently blocked: %d",#blocked))
