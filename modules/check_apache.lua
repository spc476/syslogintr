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
-- Pull stats from a locally running Apache instance.  The stats are pulled
-- from Apache's mod_status (so to use this script, you'll need to set that
-- module up in Apache).  If it can't grab the stats from Apache, a notification
-- email is sent.
--
-- params is a table with the following fields (all optional):
--
--      params.user             -- username for web authentication
--      params.password         -- password
--      params.from             -- email From: address
--      params.to               -- email To: address (can be an array)
--      params.subject          -- email Subject: line
--      params.body             -- text of the email message
--
-- This module requires the use of "wget".
--
-- *********************************************************************
-- luacheck: ignore 611

local I_log      = require "I_log"
local I_prlog    = require "I_prlog"
local send_email = require "sendmail"
local deltatime  = require "deltatime"

-- ************************************************************************
-- NO USER SERVICABLE PARTS PAST HERE---YOU SHOULD KNOW WHAT YOU ARE DOING!
-- ************************************************************************

return function(params)
  local res   = {}
  local cmd   = "wget"
  
  if params.user then
    cmd = cmd .. " --user " .. params.user
    if params.password then
      cmd = cmd .. "--password " .. params.password
    end
  end
  cmd = cmd .. " -O - " .. params.url .. " 2>/dev/null"
  
  local stats = io.popen(cmd,"r")
  
  for line in stats:lines() do
    local name,value = string.match(line,"^([^:]+): (.+)$")
    res[name] = value
  end
  
  stats:close()
  
  setmetatable(res,{ __index = function() return 0 end } )
  local msg = string.format("%s %s %s %s %s %s %s %s %s",
                res['Total Accesses'],
                res['Total kBytes'],
                res['CPULoad'],
                deltatime(res['Uptime']),
                res['ReqPerSec'],
                res['BytesPerSec'],
                res['BytesPerReq'],
                res['BusyWokers'],
                res['IdleWorkers'])
                
  if msg == "0 0 0 0s 0 0 0 0 0" then
    I_log("crit","WEB SERVER NOT RUNNING")
    send_email{
        from    = params.from    or "root",
        to      = params.to      or "root",
        subject = params.subject or "WEB SERVER NOT RUNNING",
        body    = params.body    or "WEB SERVER NOT RUNNING"
        }
    I_log("debug","past sending email")
    I_log("notice","Restarting the webserver")
    os.execute("/etc/init.d/httpd start")
  else
    I_prlog("check/httpd","notice",msg)
  end
end

