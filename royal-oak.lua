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
--
-- This is running on a management server at work, accepting log messages
-- from various routers.  Because of that, I check for certain router
-- messages, notably changes in OSPF neighbors and send notification emails.
--
-- I also convert a bunch of thin logs from Postfix into one fat log message.
--
-- ************************************************************************

require "I_log"
require "check_ospf"
require "postfix-mailsummary"
require "ssh-iptables"

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
alarm("60m")

-- **************************************************************

function alarm_handler()
  sshd_remove()
end

-- **************************************************************

function log(msg)

  if msg.facility == 'local0' and string.match(msg.msg,'UDP%: %[216%.82%.117%.164%]') then
    return
  end

  if msg.remote == false then
    msg.host = "royal-oak"
  end

  if msg.facility == 'local1' then
    check_ospf(msg,{ 
	from = "root@royal-oak.pickint.net",
	to = { "spc@pickint.net" , "admin@pickint.net"}
    })
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

I_log("debug","reloaded script")
I_log("debug",string.format("relaying to %s",tostring(homebase)))

