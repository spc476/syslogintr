
require "I_log"
require "sendmail"

local namedpid = "/var/run/named.pid"
local email = {}
      email.from    = "root@conman.org"
      email.to      = "spc@conman.org"
      email.subject = "NAME SERVER NOT RUNNING (crash?)"
      email.body    = "NAME SERVER NOT RUNNING"

-- *********************************************************************

function check_nameserver()
  local pidfile = io.open(namedpid,"r")
  if pidfile == nil then
    I_log("crit","NAME SERVER NOT RUNNING (crash?)")
    send_email(email);
    return
  end

  local pid = pidfile:read("*n")   
  pidfile:close()

  local exefile = io.open("/proc/" .. pid)
  if exefile == nil then
    I_log("crit","NAME SERVER NOT RUNNING")
    send_email(email);
    return
  end   

  exefile:close()
  I_log("debug","name server still running")
end

-- ********************************************************************

