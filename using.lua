
if blocked == nil then
  blocked = {}
end

if logfile == nil then
  logfile = io.open("/tmp/log","a")
  if logfile == nil then
    logfile = io.stdout;
  end
end

alarm("60m")

-- *******************************************************

function user_signal()
  logfile:close()
  logfile = io.open("/tmp/log","a")
  if logfile == nil then
    logfile = io.stdout;
  end
  
  log{
  	host      = "(localsocket)",
  	program   = "minsys",
  	facility  = "daemon",
  	level     = "debug",
  	timestamp = os.time(),
  	msg       = "signal received loud and clear and reset logfile"
  }
end

-- *******************************************************

function alarm_handler()
  log{
  	host       = "(localsocket)",
  	program    = "minsys",
  	facility   = "daemon",
  	level      = "debug",
  	timestatmp = os.time(),
  	msg        = "Alarm clock---snooze button!"
  }
end

-- ******************************************************

function log(msg)  
  if msg.host == "(localsocket)" or msg.level ~= "debug" then
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
  if msg.program  ~= "sshd"          then return end
  if msg.host     ~= "(localsocket)" then return end
  if msg.facility ~= "auth2"         then return end
  if msg.level    ~= "info"          then return end
  
  local ip = string.match(msg.msg,"^Failed password for .* from ::ffff:([%d%.]+) .*");
  if ip == nil then return end
  
  writelog{
  	host      = "(localsocket)",
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
    	host      = "(localsocket)",
    	program   = "minsys",
    	facility  = "daemon",
    	level     = "debug",
    	timestamp = os.time(),
    	msg       = "Command to block: " .. cmd
    }
    
    os.execute(cmd)
    blocked[ip] = nil
    
    writelog{
    	host      = "(localsocket)",
    	program   = "minsys",
    	facility  = "daemon",
    	level     = "info",
    	timestamp = os.time(),
    	msg       = "Blocked " .. ip .. " from SSH"
    }
  end
end

-- *******************************************************

log{
	host      = "(localsocket)",
	program   = "minsys",
	facility  = "daemon",
	level     = "debug",
	timestamp = os.time(),
	msg       = "reloaded script"
}

