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
    return
  end   

  exefile:close()
  I_log("debug","name server still running")
end

-- ********************************************************************

