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
-- ***************************************************************************
--
-- This file is the one I'm using on my private server.  Several years ago I
-- diverted from the RedHat standard syslog files to my own, and I kept that
-- system here.  I also direct the logs to my home system so I can monitor
-- the logs in real time (see realtime.lua).
--
-- I also convert several thin Postfix logs to one fat log (summary).
-- 
-- This configuration is pretty straight forward.
--
-- ***************************************************************************

require "I_log"
require "deltatime"
require "check_apache"
require "check_bind"
require "postfix-mailsummary"
require "proftp-iptables"
require "ssh-iptables"

-- **********************************************************************

function alarm_handler()
  check_nameserver{
  	from = "root@conman.org",
  	to   = "spc@conman.org"
  }
  check_webserver{
  	url     = "http://www.conman.org/server-status\?auto",
  	from    = "root@conman.org",
  	to      = "spc@conman.org",
  	subject = "WWW.CONMAN.ORG WEBSITE DOWN!"
  }
  proftp_remove()
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
  proftp_cleanup()
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
  logfiles.user   = io.open("/var/log/misc.log",  "a")

  logfiles.local1 = logfiles.local0
  logfiles.local2 = logfiles.local0
  logfiles.local3 = logfiles.local0
  logfiles.local4 = logfiles.local0
  logfiles.local7 = logfiles.local0
end

homebase = host("74.173.118.3")

-- **************************************************************

function log(msg)
  if msg.remote == false then
    if msg.facility == 'auth2' 
       and msg.program == 'sshd'
       and (msg.msg == 'Connection closed by 66.252.224.232' 
            or msg.msg == 'Connection closed by 66.252.227.77') then
      return
    end

    if msg.program == 'gld-pfc' then return end
    msg.host = "brevard"
  end

  if logfiles[msg.facility] == nil then
    log_to_file(logfiles.user,msg)
  else
    log_to_file(logfiles[msg.facility],msg)
  end

  sshd(msg)

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

