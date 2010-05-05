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

local url      = "http://www.conman.org/server-status\?auto"
local user     = "spc"
local password = "w2e3r4t5"

local email   = {}
      email.from    = "root@conman.org"
      email.to      = "spc@conman.org"
      email.subject = "WEB SERVER NOT RUNNING"
      email.body    = "WEB SERVER NOT RUNNING"

-- ************************************************************************
-- NO USER SERVICABLE PARTS PAST HERE---YOU SHOULD KNOW WHAT YOU ARE DOING!
-- ************************************************************************

local cmd = "wget"

if user ~= "" then
  cmd = cmd .. " --user
  if password ~= "" then
    cmd = cmd .. " --password " .. password
  end
end

cmd = cmd .. " -O - " .. url .. " 2>/dev/null"

-- **********************************************************************

function check_webserver()
  local res   = {}
  local stats = io.popen(cmd,"r")

  for line in stats:lines() do
    local name,value = string.match(line,"^([^:]+): (.+)$")
    res[name] = value
  end

  stats:close()

  setmetatable(res,{ __index = function(t,k) return 0 end } )
  local msg = string.format("%s %s %s %s %s %s %s %s %s",
                res['Total Accesses'],
                res['Total kBytes'],
                res['CPULoad'],
                delta_time(res['Uptime']),
                res['ReqPerSec'],  
                res['BytesPerSec'],
                res['BytesPerReq'],
                res['BusyWokers'], 
                res['IdleWorkers'])

  if msg == "0 0 0 0s 0 0 0 0 0" then
    I_log("crit","WEB SERVER NOT RUNNING")
    send_emergency_email(email)
  else  
    log{
        host      = "(internal)",
        remote    = false,
        program   = "check/httpd",
        facility  = "daemon", 
        level     = "info",   
        timestamp = os.time(),
        msg       = msg
    }
  end
end

