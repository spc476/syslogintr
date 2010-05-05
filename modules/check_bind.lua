-- ***************************************************************
--
-- Copyright 2010 by Sean Conner.  All Rights Reserved.
-- 
-- This program is free software; you can redistribute it and/or
-- modify it under the terms of the GNU General Public License
-- as published by the Free Software Foundation; either version 2
-- of the License, or (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, write to the Free Software
-- Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
--
-- Comments, questions and criticisms can be sent to: sean@conman.org
--
-- ********************************************************************

require "I_log"
require "sendmail"

local namedpid = "/var/run/named.pid"
local email = {}
      email.from    = "root@conman.org"
      email.to      = "spc@conman.org"
      email.subject = "NAME SERVER NOT RUNNING (crash?)"
      email.body    = "NAME SERVER NOT RUNNING"

-- *********************************************************************

function check_nameserver()
  local pidfile = io.open(namedpid,"r")
  if pidfile == nil then
    I_log("crit","NAME SERVER NOT RUNNING (crash?)")
    send_email(email);
    return
  end

  local pid = pidfile:read("*n")   
  pidfile:close()

  local exefile = io.open("/proc/" .. pid)
  if exefile == nil then
    I_log("crit","NAME SERVER NOT RUNNING")
    send_email(email);
    return
  end   

  exefile:close()
  I_log("debug","name server still running")
end

-- ********************************************************************

