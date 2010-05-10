-- ***************************************************************
--
-- Copyright 2010 by Sean Conner.  All Rights Reserved.
-- 
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program.  If not, see <http://www.gnu.org/licenses/>.
--
-- Comments, questions and criticisms can be sent to: sean@conman.org
--
-- ********************************************************************

-- ******************************************************************
-- * A file the duplicates a default install of RedHat and their
-- * syslog.conf file.  All functions not labeled as "local" are called
-- * directly via the runtime engine.  
-- *
-- * cleanup()		- called when the daemon exits
-- * reload_signal()	- called when the program recieves a SIGHUP
-- * log()		- called each time the daemon receives a message
-- * 
-- * This is provided as a means to replace syslogd with a drop in
-- * replacement, but with the ability to expand upon the functionality
-- * as required.
-- *******************************************************************

function cleanup()
  messages:close()
  secure:close()
  maillog:close()
  cron:close()
  spooler:close()
  boot:close()
end

-- *********************************************************************

local function openfiles()
  messages = io.open("/var/log/messages","a") or io.stdout
  secure   = io.open("/var/log/secure"  ,"a") or io.stdout
  maillog  = io.open("/var/log/maillog" ,"a") or io.stdout
  cron     = io.open("/var/log/cron"    ,"a") or io.stdout
  spooler  = io.open("/var/log/spooler" ,"a") or io.stdout
  boot     = io.open("/var/log/boot"    ,"a") or io.stdout
end

openfiles()

-- *********************************************************************

function reload_signal()
  cleanup()
  openfiles()
end

-- *********************************************************************

local function logfile(msg,file,flushp)
  local flushp = flushp or false
  
  if msg.remote == false then
    msg.host = "localhost"
  end
  
  file:write(string.format(
  	"%s %s %s[%d]: %s\n",
  	os.date("%b %d %H:%M:%S",msg.timestamp),
  	msg.host,
  	msg.program,
  	msg.pid,
  	msg.msg
  ))
  
  if flushp then file:flush() end
end
  
-- ******************************************************************  

local function everybody(msg)
  local out = io.popen("/usr/bin/wall","w")
  logfile(msg,out)
  out:close()
end

-- ******************************************************************

function log(msg)
  if msg.level == 'info'   or
     msg.level == 'notice' or
     msg.level == 'warn'   or
     msg.level == 'err'    or
     msg.level == 'crit'   or
     msg.level == 'alert'  or
     msg.level == 'emerg' then
       if msg.facility ~= 'mail'  and
          msg.facility ~= 'auth2' and
          msg.facility ~= 'cron'  and
          msg.facility ~= 'local6' then
            logfile(msg,messages)
          end
     end

  if msg.facility == 'auth2' then
    logfile(msg,secure)
  end
  
  if msg.facility == 'mail' then
    logfile(msg,maillog,true)
  end
  
  if msg.facility == 'cron' then
    logfile(msg,cron)
  end
  
  if msg.level == 'emerg' then
    everybody(msg)
  end
  
  if msg.facility == 'uucp' or
     msg.facility == 'news' then
       if msg.level == 'crit' or
          msg.level == 'alert' or
          msg.level == 'emerg' then
            logfile(msg,spooler)
          end
      end

  if msg.facility == 'local7' then
    logfile(msg,boot)
  end
end

-- ********************************************************************

