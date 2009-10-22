
messages = io.open("/var/log/messages","a") or io.stdout
secure   = io.open("/var/log/secure"  ,"a") or io.stdout
maillog  = io.open("/var/log/maillog" ,"a") or io.stdout
cron     = io.open("/var/log/cron"    ,"a") or io.stdout
spooler  = io.open("/var/log/spooler" ,"a") or io.stdout
boot     = io.open("/var/log/boot"    ,"a") or io.stdout

-- *********************************************************************

function logfile(msg,file,flushp)
  local flushp = flushp or true
  
  file:write(string.format(
  	"%s %s %s[%d]: %s\n",
  	os.date("%c",msg.timestamp),
  	msg.host,
  	msg.program,
  	msg.pid,
  	msg.msg
  ))
  
  if flushp then file:flush() end
end
  
-- ******************************************************************  

function everybody(msg)
  local out = io.popen("/usr/bin/wall","w")
  logfile(msg,out)
  out:close()
end

-- ******************************************************************

function log(msg)
  if log.level == 'info'   or
     log.level == 'notice' or
     log.level == 'warn'   or
     log.level == 'err'    or
     log.level == 'crit'   or
     log.level == 'alert'  or
     log.level == 'emerg' then
       if log.facility ~= 'mail'  and
          log.facility ~= 'auth2' and
          log.facility ~= 'cron'  and
          log.facility ~= 'local6' then
            logfile(msg,messages)
          end
     end

  if log.facility == 'auth2' then
    logfile(msg,secure)
  end
  
  if log.facility == 'mail' then
    logfile(msg,maillog,false)
  end
  
  if log.facility == 'cron' then
    logfile(msg,cron)
  end
  
  if log.level == 'emerg' then
    everybody(msg)
  end
  
  if log.facility == 'uucp' or
     log.facility == 'news' then
       if log.level == 'crit' or
          log.level == 'alert' or
          log.level == 'emerg' then
            logfile(msg,spooler)
          end
      end

  if log.facility == 'local7' then
    logfile(msg,boot)
  end
end

