
-- **********************************************************************

function delta_time(diff)

  if diff == 0 then return "0s" end

  local SECSMIN  = 60.0
  local SECSHOUR = SECSMIN  * 60.0
  local SECSDAY  = SECSHOUR * 24.0
  local SECSYEAR = SECSDAY  * 365.242199

  local year = math.floor(diff / SECSYEAR) diff = diff - (year * SECSYEAR)
  local day  = math.floor(diff / SECSDAY)  diff = diff - (day  * SECSDAY)
  local hour = math.floor(diff / SECSHOUR) diff = diff - (hour * SECSHOUR)
  local min  = math.floor(diff / SECSMIN)  diff = diff - (min  * SECSMIN)
  local sec  = math.floor(diff)
  local out  = ""

  if year ~= 0 then out = out .. string.format("%dy",year)  end
  if day  ~= 0 then out = out .. string.format(".%dd",day)  end
  if hour ~= 0 then out = out .. string.format(".%dh",hour) end
  if min  ~= 0 then out = out .. string.format(".%dm",min)  end
  if sec  ~= 0 then out = out .. string.format(".%ds",sec)  end

  return out
end

-- ********************************************************************

function send_emergency_email(text)
  I_log("debug","about to send email")
  local sendmail = io.popen("/usr/sbin/sendmail spc@conman.org","w")
  if sendmail == nil then
    I_log("crit","nonexec of sendmail")
    return
  end

  sendmail:write(string.format([[
From: root@conman.org
To: spc@conman.org
Subject: %s
Date: %s

%s

]],
	text,
	os.date("%a, %d %b %Y %H:%M:%S %Z",os.time()),
	text))
  sendmail:close()
  I_log("debug","sent email")
end

-- *********************************************************************

function check_webserver()
  local res   = {}
  local stats = io.popen("wget -O - http://www.conman.org/server-status\?auto 2>/dev/null","r")
  
  for line in stats:lines() do
    local name,value = string.match(line,"^([^:]+): (.+)$")
    res[name] = value
  end

  stats:close()

  setmetatable(res,{ __index = function(t,k) return 0 end } )
  local msg = string.format("%s %s %s %s %s %s %s %s %s",
		res['Total Accesses'],
		res['Total kBytes'],
		res['CPULoad'],
		delta_time(res['Uptime']),
		res['ReqPerSec'],
		res['BytesPerSec'],
		res['BytesPerReq'],
		res['BusyWokers'],
		res['IdleWorkers'])

  if msg == "0 0 0 0s 0 0 0 0 0" then
    I_log("crit","WEB SERVER NOT RUNNING")
    send_emergency_email("WEB SERVER NOT RUNNING")
  else
    log{
	host      = "(internal)",
	remote    = false,
	program   = "check/httpd",
	facility  = "daemon",
	level     = "info",
	timestamp = os.time(),
	msg       = msg
    }
  end
end

-- **********************************************************************

function check_nameserver()
  local pidfile = io.open("/var/run/named.pid")
  if pidfile == nil then
    I_log("crit","NAME SERVER NOT RUNNING (crash?)")
    send_emergency_email("NAME SERVER NOT RUNNING (crash?)")
    return
  end

  local pid = pidfile:read("*n")
  pidfile:close()
  
  local exefile = io.open("/proc/" .. pid)
  if exefile == nil then
    I_log("crit","NAME SERVER NOT RUNNING")
    send_emergency_email("NAME SERVER NOT RUNNING")
    return
  end

  exefile:close()
  I_log("debug","name server still running")
end

-- ***********************************************************************

function alarm_handler()
  check_webserver()
  check_nameserver()
end

-- **********************************************************************

function cleanup()
  logfiles.auth1:close()
  logfiles.mail:close()
  logfiles.daemon:close()
  logfiles.kern:close()
  logfiles.cron1:close()
  logfiles.local5:close()
  logfiles.local6:close()
  logfiles.local0:close()
  logfiles.user:close()
end

-- *********************************************************************

function open_files()
  logfiles        = {}
  logfiles.auth1  = io.open("/var/log/auth.log",  "a")
  logfiles.mail   = io.open("/var/log/mail.log",  "a")
  logfiles.daemon = io.open("/var/log/daemon.log","a")
  logfiles.kern   = io.open("/var/log/kern.log",  "a")
  logfiles.cron1  = io.open("/var/log/cron.log",  "a")
  logfiles.local5 = io.open("/var/log/local5.log","a")
  logfiles.local6 = io.open("/var/log/local6.log","a")
  logfiles.local0 = io.open("/var/log/local.log" ,"a")
  logfiles.user   = io.open("/var/log/misc.log","a")

  logfiles.local1 = logfiles.local0
  logfiles.local2 = logfiles.local0
  logfiles.local3 = logfiles.local0
  logfiles.local4 = logfiles.local0
  logfiles.local7 = logfiles.local0
end

homebase = host("lucy.roswell.conman.org")

if maillist == nil then
  maillist = {}
end


-- **************************************************************

function log(msg)
  if msg.remote == false then
    if msg.facility == 'auth2' 
       and msg.program == 'sshd'
       and (msg.msg == 'Connection closed by 66.252.224.232' 
            or msg.msg == 'Connection closed by 66.252.227.77') then
      return
    end
    msg.host = "brevard"
  end

  if logfiles[msg.facility] == nil then
    log_to_file(logfiles.user,msg)
  else
    log_to_file(logfiles[msg.facility],msg)
  end

  if mailsummary(msg) then
    relay(homebase,msg)
  end
end

-- **************************************************************

function reload_signal()
  if logfiles ~= nil then
    cleanup()
    open_files()
  end

  I_log("debug","signal received loud and clear; reset logfiles")
end

-- *************************************************************

function I_log(level,msg)
  log{
  	host      = "(internal)",
  	remote    = false,
  	program   = script,
  	facility  = "daemon",
  	level     = level,
  	timestamp = os.time(),
  	msg       = msg
  }
end

-- **************************************************************

function log_to_file(file,msg)
  file:write(string.format(
	"%s %s %s: %s\n",
	os.date("%b %d %H:%M:%S",msg.timestamp),
	msg.host,
	msg.program,
	msg.msg
  ));
  file:flush()
end

-- ******************************************************************

function mailsummary(msg)
  if msg.program == 'gld' then return false end
  if string.find(msg.program,'postfix/',1,true) == nil then return true end
  if msg.facility ~= 'mail' then return true end
  if msg.level    ~= 'info' then return true end

  local email
  local id
  local data
  
  local function getemail(id)
    if maillist[id] == nil then
      maillist[id] = {}
    end
    return maillist[id]
  end

  if string.match(msg.msg,'^%S+%: client=.*') then
    id,data      = string.match(msg.msg,'^(%S+)%: client=(.*)$')
    if id == nil then
      return true
    end
    email        = getemail(id)
    email.client = data
    return false

  elseif string.match(msg.msg,'^%S+%: message%-id=.*') then
    id,data  = string.match(msg.msg,'^(%S+)%: message%-id=%<(%S+)%>')
    if id == nil then
      return true
    end
    email    = getemail(id)
    email.id = data
    return false

  elseif string.match(msg.msg,'^%S+%: from=.*') then
    id,data    = string.match(msg.msg,'^(%S+)%: from=%<(%S*)%>')
    if id == nil then
      return true
    end
    email      = getemail(id)
    email.from = data
    return false

  elseif string.match(msg.msg,'^%S+%: to=.*') then
    id,data,status = string.match(msg.msg,'^(%S+)%: to=%<(%S+)%>.* status=(%S+)')
    if id == nil then
      return true
    end
    email        = getemail(id)
    email.to     = data
    email.status = status
    return false

  elseif string.match(msg.msg,'^%S+%: removed') then
    id    = string.match(msg.msg,'^(%S+)%:')
    
    if id == nil then
      return true
    end

    email = getemail(id)
    
    if email.client == nil then email.client = "(na)" end
    if email.from   == nil then email.from   = ""     end
    if email.to     == nil then email.to     = "(na)" end
    if email.status == nil then email.status = "(unknown)" end
    msg.program = 'summary/mail'
    msg.msg     = string.format(
    			"client=%s message-id=<%s> from=<%s> to=<%s> status=%s",
    			email.client,
    			email.id,
    			email.from,
    			email.to,
                        email.status
    			)    	
    maillist[id] = nil
    return true
  end

  return false
end	

-- ******************************************************************

if logfiles == nil then
  open_files()
end

alarm("60m")
alarm_handler()
I_log("debug","reloaded script")
I_log("debug",string.format("relaying to %s",tostring(homebase)))

