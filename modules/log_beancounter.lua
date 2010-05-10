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

function log_bean()
  local uid
  local resource
  local held
  local maxheld
  local barrier
  local limit
  local failcnt
  local line
  local file = io.open("/proc/user_beancounters","r")

  line = file:read("*l") -- burn Version line
  line = file:read("*l") -- burn header line
  line = file:read("*l") -- first line of read input

  uid,resource,held,maxheld,barrier,limit,failcnt = line:match("^%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)")
  if tonumber(failcnt) > 0 then
    I_prlog("check/beancounters","notice",string.format("%s h=%s m=%s b=%s l=%s f=%s\n",resource,held,maxheld,barrier,limit,failcnt))
  end

  for line in file:lines() do
    resource,held,maxheld,barrier,limit,failcnt = line:match("^%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)")
    if tonumber(failcnt) > 0 then
      I_prlog("check/beancounters","notice",string.format("%s h=%s m=%s b=%s l=%s f=%s\n",resource,held,maxheld,barrier,limit,failcnt))
    end
  end
  file:close()
end
