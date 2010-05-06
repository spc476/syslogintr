
require "I_log"
require "check_ospf"
require "postfix-mailsummary"

-- **********************************************************************

function cleanup()
  logfiles.auth1:close()
  logfiles.mail:close()
  logfiles.daemon:close()
  logfiles.kern:close()
  logfiles.cron1:close()
  logfiles.local0:close()
  logfiles.local1:close()
  logfiles.local2:close()
  logfiles.local4:close()
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
  logfiles.misc   = io.open("/var/log/misc.log",  "a")
  logfiles.local0 = io.open("/var/log/local0.log","a")
  logfiles.local1 = io.open("/var/log/local1.log","a")
  logfiles.local2 = io.open("/var/log/local.log" ,"a")
  logfiles.local4 = io.open("/var/log/local4.log","a")
  logfiles.user   = io.open("/var/log/misc.log","a")
end

homebase = host("74.173.118.3")

-- **************************************************************

function log(msg)

  if msg.facility == 'local0' and string.match(msg.msg,'UDP%: %[216%.82%.117%.164%]') then
    return
  end

  if msg.remote == false then
    msg.host = "royal-oak"
  end

  if msg.facility == 'local1' then
    check_ospf(msg,{})
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

I_log("debug","reloaded script")
I_log("debug",string.format("relaying to %s",tostring(homebase)))

