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
-- Check to see if named is running (yes, I have a machine where named
-- stops running.  I know why it happens, but I can't fix it (long story).
-- Anyway, checks to see if named is running on a Linux system (or at least
-- a Unix system that suports the /proc filesystem).  If it's not running,
-- an email notification is sent.
--
-- params is a table with the following optional fields:
--
--      params.from             -- From: address
--      params.to               -- To: address (can be an array of addresses)
--      params.subject          -- Subject: line
--      params.body             -- body of the email
--
-- **********************************************************************

require "I_log"
require "sendmail"

local namedpid = "/var/run/named.pid"

-- *********************************************************************

function check_nameserver(params)
  local pidfile = io.open(namedpid,"r")
  if pidfile == nil then
    I_log("crit","NAME SERVER NOT RUNNING (crash?)")
    send_email{
        from    = params.from    or "root@conman.org",
        to      = params.to      or "spc@conman.org",
        subject = params.subject or "NAME SERVER NOT RUNNING (crash?)",
        body    = params.body    or "NAME SERVER NOT RUNNING"
    }
    I_log("notice","Restarting named")
    os.execute("/etc/init.d/named start")
    return
  end
  
  local pid = pidfile:read("*n")
  pidfile:close()
  
  local exefile = io.open("/proc/" .. pid)
  if exefile == nil then
    I_log("crit","NAME SERVER NOT RUNNING")
    send_email{
        from    = params.from    or "root@conman.org",
        to      = params.to      or "spc@conman.org",
        subject = params.subject or "NAME SERVER NOT RUNNING",
        body    = params.body    or "NAME SERVER NOT RUNNING"
    }
    I_log("notice","Restarting named")
    os.execute("/etc/init.d/named start")
    return
  end
  
  exefile:close()
  I_log("debug","name server still running")
end

-- ********************************************************************

