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
-- Keep a count of the remote hosts sending in log messages.
--
-- inc_hostcount(host)          -- call for each message received
-- log_hostcounts()             -- call to log number of msgs from each host.
--                                 The counters are reset to 0.
--
-- ***********************************************************************
-- luacheck: ignore 611
-- luacheck: globals g_hostcount

local string  = require "string"
local I_prlog = require "I_prlog"

local pairs   = pairs

if g_hostcount == nil then
  g_hostcount = setmetatable({},{__index = function() return 0 end })
end

-- ********************************************************************

return {
  inc = function(host)
    g_hostcount[host] = g_hostcount[host] + 1
  end,
  
  -- ======================================================
  
  log = function()
    local s = ""
    
    for name,value in pairs(g_hostcount) do
      s = s .. string.format("%s:%s",name,value)
      if value == 0 then
        g_hostcount[name] = nil
      else
        g_hostcount[name] = 0
      end
    end
    
    I_prlog("summary/hosts",'info',s)
  end,
}
