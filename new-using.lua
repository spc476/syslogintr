
package.path = "/home/spc/source/sysloginter/modules/?.lua"

require "I_log"
require "ssh-iptables"

-- *********************************************************************

if logfile == nil then
  logfile = io.open("/var/log/syslog","a") or io.stdout
end

if hostlist == nil then
  hostlist = {}
  setmetatable(hostlist,{ __index = function(t,k) return 0 end })
end

alarm("60m")

-- ***********************************************************************

function log(msg)

  -- ====================================================
  -- Bunny's machine is sending the hostname, which is
  -- being interpreted as a program name.  This corrects
  -- for that.
  -- ====================================================
  
  if msg.host == '192.168.1.16' then
    msg.program = string.match(msg.program,'^.*%s+(.*)')
  end

  hostlist[msg.host] = hostlist[msg.host] + 1
  
  writelog(logfile,msg)
  sshd(msg)
end

-- **********************************************************************

function alarm_handler()
  sshd_remove()
  log_hosts()
end

-- **********************************************************************

function reload_signal()
  if logfile ~= io.stdout then
    logfile:close()
    logfile = io.open("/var/log/syslog","a") or io.stdout
  end
  
  log_hosts()
  I_log("debug","signal received loud and clean and reset logfile")
end

-- **********************************************************************

function cleanup()
  sshd_cleanup()
  logfile:close()
end

-- ***********************************************************************

local function writelog(file,msg)
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

-- **********************************************************************

local function log_hosts()
  local s = ""
  
  for name,value in pairs(hostlist) do
    s = s .. string.format("%s:%d ",name,value)
    hostlist[name] = 0
  end
  
  I_prlog("check/remotehosts","info",s)
end

-- *********************************************************************

