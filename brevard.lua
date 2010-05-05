
require "I_log"
require "deltatime"
require "check_apache"
require "check_bind"
require "postfix-mailsummary"

-- **********************************************************************

function alarm_handler()
  check_nameserver()
  check_webserver()
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

-- **************************************************************

function log(msg)
  if msg.remote == false then
    if msg.facility == 'auth2' 
       and msg.program == 'sshd'
       and (msg.msg == 'Connection closed by 66.252.224.232' 
            or msg.msg == 'Connection closed by 66.252.227.77') then
      return
    end

    if msg.program == 'gld' then return end
    msg.host = "brevard"
  end

  if logfiles[msg.facility] == nil then
    log_to_file(logfiles.user,msg)
  else
    log_to_file(logfiles[msg.facility],msg)
  end

  if postfix_mailsummary(msg) then
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

if logfiles == nil then
  open_files()
end

alarm("60m")
alarm_handler()
I_log("debug","reloaded script")
I_log("debug",string.format("relaying to %s",tostring(homebase)))

