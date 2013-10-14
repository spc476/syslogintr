-- ***************************************************************
--
-- Copyright 2013 by Sean Conner.  All Rights Reserved.
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
-- collect logs from proftpd, and if there are 5 fail attempts at logging
-- in, block the offending IP address.
--
-- proftp(msg)		-- check for proftpd messages and track failed logins
-- proftp_remove()	-- periodically call this to remove old blocked IP
--			   addresses
--
-- This module assume the use of iptables.  Please make sure you have
-- run the following:
--
--	iptables -N proftp-block
--	iptables -A INPUT -p tcp --dport 21 -j proftp-block
--
-- ***********************************************************************

require "I_log"

if proftp_blocked == nil then
  proftp_blocked = {}
  setmetatable(proftp_blocked,{ __index = function(t,k) return 0 end })
  os.execute("iptables --table filter -F proftp-block")
end

-- ********************************************************************

function proftp(msg)
  if msg.remote   == true      then return end
  if msg.program  ~= "proftpd" then return end
  if msg.facility ~= "daemon"  then return end
  if msg.level    ~= "notice"  then return end

  local ip = string.match(msg.msg,"User: %S+: no such user found from ::ffff:([%d%.]+)")
  if ip == nil then return end

  I_log("debug","Found IP:" .. ip)
  
  proftp_blocked[ip] = proftp_blocked[ip] + 1

  if proftp_blocked[ip] >= 5 then
    local cmd = "iptables --table filter --append proftp-block --source " .. ip .. " --proto tcp --dport 21 --jump REJECT"
    I_log("debug","Command to block: " .. cmd)    
    os.execute(cmd)    
    I_log("info","Blocked " .. ip .. " from ProFTPd")
    table.insert(proftp_blocked,{ ip = ip , when = msg.timestamp} )
  end
end

-- **************************************************************

function proftp_remove()
  local now = os.time()
  
  while #proftp_blocked > 0 do
    if now - proftp_blocked[1].when < 3600 then return end
    local ip = proftp_blocked[1].ip
    I_log("info","Removing IP block: " .. ip)
    proftp_blocked[ip] = nil
    table.remove(proftp_blocked,1)
    os.execute("iptables --table filter -D proftp-block 1")
  end
  
  if #proftp_blocked > 0 then
    I_log("debug",string.format("%d still proftp_blocked",#proftp_blocked))
  end
end

-- ****************************************************************

function sshd_cleanup()
  proftp_blocked = {}
  setmetatable(proftp_blocked,{ __index = function(t,k) return 0 end })
  os.execute("iptables --table filter -F proftp-block")
end

-- *****************************************************************

