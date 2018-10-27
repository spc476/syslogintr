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
-- luacheck: ignore 611
-- luacheck: ignore host alarm relay
-- luacheck: globals logfiles cleanup alarm_handler log reload_signal

local I_log               = require "I_log"
local check_ospf          = require "check_ospf"
local postfix_mailsummary = require "postfix-mailsummary"
local ssh                 = require "ssh-iptables"

local homebase = host("74.173.118.3")

-- **********************************************************************

local function open_files()
  logfiles        = {}
  logfiles.auth1  = io.open("/var/log/auth.log",  "a")
  logfiles.auth2  = io.open("/var/log/auth2.log", "a")
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

-- **************************************************************

local function log_to_file(file,msg)
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

function cleanup()
  logfiles.auth1:close()
  logfiles.auth2:close()
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

function alarm_handler()
  ssh.remove()
end

-- **************************************************************

function log(msg)
  if msg.host == '216.242.158.235' then
    return
  end
  
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
  
  ssh.log(msg)
  
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

if logfiles == nil then
  open_files()
end

alarm("60m")
I_log("debug","reloaded script")
I_log("debug",string.format("relaying to %s",tostring(homebase)))
