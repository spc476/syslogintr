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

if hostcount == nil then
  hostcount = setmetatable({},{__index = function(t,k) return 0 end })
end

-- ********************************************************************

function log_hostcounts()
  local s = ""
  
  for name,value in pairs(hostcount) do
    s = s .. string.format("%s:%d ",name,value)
    hostcount[name] = 0
  end
  
  I_prlog("summary/hosts","info",s)
end

-- *********************************************************************

function inc_hostcount(host)
  hostcount[host] = hostcount[host] + 1
end

-- ********************************************************************

