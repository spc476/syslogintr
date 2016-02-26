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
-- collect logs from ssh, and if there are 5 fail attempts at logging in,
-- block the offending IP address.  
--
-- sshd(msg)		-- check for ssh messages and track failed logins
-- sshd_remove()	-- periodically call this to remove old blocked IP
--			   addresses
--
-- This module assume the use of iptables.  It also adds rules to the
-- main chain.  This should be fixed.
--
-- ***********************************************************************

require "I_log"

if ssh_blocked == nil then
  ssh_blocked = {}
  setmetatable(ssh_blocked,{ __index = function(t,k) return 0 end })
  os.execute("iptables --table filter -F ssh-block")
end

-- ********************************************************************

function sshd(msg)
  if msg.remote   == true    then return end
  if msg.program  ~= "sshd"  then return end
  if msg.facility ~= "auth2" then return end
  if msg.level    ~= "info"  then return end

  local ip = string.match(msg.msg,"^Failed password for .* from ::ffff:([%d%.]+).*")
  if ip == nil then return end

  I_log("debug","Found IP:" .. ip)
  
  ssh_blocked[ip] = ssh_blocked[ip] + 1

  if ssh_blocked[ip] == 5 then
    local cmd = "iptables --table filter --append ssh-block --source " .. ip .. " --jump REJECT"
    I_log("debug","Command to block: " .. cmd)    
    os.execute(cmd)    
    I_log("info","Blocked " .. ip .. " from SSH")
    table.insert(ssh_blocked,{ ip = ip , when = msg.timestamp} )
  end
end

-- **************************************************************

function sshd_remove()
  local now = os.time()
  
  while #ssh_blocked > 0 do
    -- --------------------------------------------------------------------
    -- block for a month (30d 10h 30m) as apparently botnets give up after
    -- being blocked for two weeks.
    -- --------------------------------------------------------------------
    
    if now - ssh_blocked[1].when < 2629800 then 
      return 
    end
    
    local ip = ssh_blocked[1].ip
    I_log("info","Removing IP block: " .. ip)
    ssh_blocked[ip] = nil
    table.remove(ssh_blocked,1)
    os.execute("iptables --table filter -D ssh-block 1")
  end
  
  if #ssh_blocked > 0 then
    I_log("debug",string.format("%d still ssh_blocked",#ssh_blocked))
  end
end

-- ****************************************************************

function sshd_cleanup()
  ssh_blocked = {}
  setmetatable(ssh_blocked,{ __index = function(t,k) return 0 end })
  os.execute("iptables --table filter -F ssh-block")
end

-- *****************************************************************

