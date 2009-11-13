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
end

if logfile == nil then
  logfile = io.open("/tmp/log","a") or io.stdout;
end

alarm("60m")

-- *******************************************************

function user_signal()
  if logfile ~= io.stdout then
    logfile:close()
    logfile = io.open("/tmp/log","a") or io.stdout;
  end
  
  log{
  	host      = "(internal)",
  	remote    = false,
  	program   = "minsys",
  	facility  = "daemon",
  	level     = "debug",
  	timestamp = os.time(),
  	msg       = "signal received loud and clear and reset logfile"
  }
end

-- *******************************************************

function alarm_handler()
  if #blocked == 0 then
    log{
  	host       = "(internal)",
  	remote     = false,
  	program    = "minsys",
  	facility   = "daemon",
  	level      = "debug",
  	timestatmp = os.time(),
  	msg        = "Alarm clock---snooze button!"
    }
    return
  end
  
  local now = os.time()
  
  while #blocked > 0 do
    if now - blocked[1].when > 3600 then
      local ip = blocked[1].ip
      
      log{
      		host      = "(internal)",
      		remote    = false,
      		program   = "minsys",
      		facility  = "daemon",
      		level     = "debug",
      		timestamp = now,
      		msg       = "Removing IP block: " .. ip
      	}
      	
      blocked[ip] = nil
      table.remove(blocked,1)
      os.execute("iptables --table filter -D INPUT 1")
      break;
    end
  end
end

-- ******************************************************

function log(msg)  
  if msg.remote == false or msg.level ~= "debug" then
    writelog(msg)
    sshd(msg)
  end
end

-- ********************************************************
  
function writelog(msg)
  logfile:write(string.format(
  		"%15.15s | %-25.25s | %-8s %6s | %s | %s\n",
  		msg.host,
  		msg.program,
  		msg.facility,
  		msg.level,
  		os.date("%c",msg.timestamp),
  		msg.msg
  	))
  logfile:flush()
end

-- ********************************************************

function sshd(msg)
  if msg.program  ~= "sshd"       then return end
  if msg.host     ~= "(internal)" then return end
  if msg.facility ~= "auth2"      then return end
  if msg.level    ~= "info"       then return end
  
  local ip = string.match(msg.msg,"^Failed password for .* from ::ffff:([%d%.]+) .*");
  if ip == nil then return end
  
  writelog{
  	host      = "(internal)",
  	remote    = false,
  	program   = "minsys",
  	facility  = "daemon",
  	level     = "debug",
  	timestamp = os.time(),
  	msg       = "Found IP:" .. ip
  }

  if blocked[ip] == nil then
    blocked[ip] = 1
  else
    blocked[ip] = blocked[ip] + 1
  end
  
  if blocked[ip] == 5 then
    local cmd = "iptables --table filter --append INPUT --source " .. ip .. " --proto tcp --dport 22 --jump REJECT"
    
    writelog{
    	host      = "(internal)",
    	remote    = false,
    	program   = "minsys",
    	facility  = "daemon",
    	level     = "debug",
    	timestamp = os.time(),
    	msg       = "Command to block: " .. cmd
    }
    
    os.execute(cmd)
    
    writelog{
    	host      = "(internal)",
    	remote    = false,
    	program   = "minsys",
    	facility  = "daemon",
    	level     = "info",
    	timestamp = os.time(),
    	msg       = "Blocked " .. ip .. " from SSH"
    }
    
    table.insert(blocked,{ ip = ip , when = msg.timestamp} )

  end
end

-- *******************************************************

log{
	host      = "(internal)",
	remote    = false,
	program   = "minsys",
	facility  = "daemon",
	level     = "debug",
	timestamp = os.time(),
	msg       = "reloaded script"
}

