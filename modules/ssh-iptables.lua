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
-- sshd(msg)            -- check for ssh messages and track failed logins
-- sshd_remove()        -- periodically call this to remove old blocked IP
--                         addresses
--
-- This module assume the use of iptables.  It also adds rules to the
-- main chain.  This should be fixed.
--
-- ***********************************************************************
-- luacheck: ignore 611
-- luacheck: globals ssh_blocked log remove cleanup

local os     = require "os"
local io     = require "io"
local string = require "string"
local table  = require "table"
local I_log  = require "I_log"
local lpeg   = require "lpeg"
local IP     = require "org.conman.parsers.ip-text".IPv4

local _VERSION     = _VERSION
local setmetatable = setmetatable
local pairs        = pairs
local tonumber     = tonumber

if _VERSION == "Lua 5.1" then
  module(...)
else
  _ENV = {}
end

-- ********************************************************************

if ssh_blocked == nil then
  ssh_blocked = {}
  setmetatable(ssh_blocked,{ __index = function() return 0 end })
  os.execute("iptables --table filter -F ssh-block")
end

-- ********************************************************************

local failed do
  local id = lpeg.P"invalid user "^-1 * (lpeg.P(1) - lpeg.P" ")^1
  local ip = lpeg.P"::ffff:"^-1 * lpeg.C(IP)
  failed   = lpeg.P"Failed " * (lpeg.P"password" + lpeg.P"none") * lpeg.P" for " * id * " from " * ip
           + lpeg.P"Did not receive identification string from " * ip
end

function log(msg)
  if msg.remote   == true    then return end
  if msg.program  ~= "sshd"  then return end
  if msg.facility ~= "auth2" then return end
  if msg.level    ~= "info"  then return end
  
  local ip = failed:match(msg.msg)
  if ip == nil then return end
  
  ssh_blocked[ip] = ssh_blocked[ip] + 1

  I_log('debug',string.format("Found IP: %s %d",ip,ssh_blocked[ip]))
  
  if ssh_blocked[ip] == 5 then
    local cmd = "iptables --table filter --append ssh-block --source " .. ip .. " --jump REJECT"
    I_log("debug","Command to block: " .. cmd)
    os.execute(cmd)
    I_log("info","Blocked " .. ip .. " from SSH")
    table.insert(ssh_blocked,{ ip = ip , when = msg.timestamp} )
  end
end

-- **************************************************************

local parseline do
  local Cg = lpeg.Cg
  local Ct = lpeg.Ct
  local R  = lpeg.R
  local P  = lpeg.P
  
  local num   = R"09"^1 / tonumber
  local field = R"!~"^1
  local sep   = P" "^1
  parseline = Ct(
                    Cg(num  ,'num')         * sep
                  * Cg(field,'packets')     * sep
                  * Cg(field,'bytes')       * sep
                  * Cg(field,'target')      * sep
                  * Cg(field,'prot')        * sep
                  * Cg(field,'opt')         * sep
                  * Cg(field,'in')          * sep
                  * Cg(field,'out')         * sep
                  * Cg(field,'source')      * sep
                  * Cg(field,'destination') * sep
                  * Cg(field,'rule')        * sep
                  * Cg(field,'why')
                )
end

function remove()
  local rules = io.open("/sbin/iptables --list ssh-block -vn --line","r")
  rules:read("*l")
  rules:read("*l")
  local list = {}
  
  for rule in rules:lines() do
    local data = parseline:match(rule)
    if data then
      list[data.source] = data
    else
      I_log('error',"ssh-iptable parse error: %q",data)
    end
  end
  
  local now    = os.time()
  local remove = {}
  
  while #ssh_blocked > 0 do
    -- --------------------------------------------------------------------
    -- block for 15 days as apparently botnets give up after
    -- being blocked for two weeks.
    -- --------------------------------------------------------------------
    
    if now - ssh_blocked[1].when < (15 * 86400) then
      return
    end
    
    local entry = table.remove(ssh_blocked,1)
    ssh_blocked[entry.ip] = nil
    table.insert(remove,list[entry.ip])
  end
  
  if #remove > 0 then
    table.sort(remove,function(a,b) return a.num > b.num end)
  
    for _,item in pairs(remove) do
      I_log("info",string.format("Removing IP block %d: %s",item.num,item.source))
      os.execute("iptables --table filter -D ssh-block " .. item.num)
    end
  end
  
  if #ssh_blocked > 0 then
    I_log("debug",string.format("%d still ssh_blocked",#ssh_blocked))
  end
end

-- ****************************************************************

function cleanup()
  ssh_blocked = {}
  setmetatable(ssh_blocked,{ __index = function() return 0 end })
  os.execute("iptables --table filter -F ssh-block")
end

-- *****************************************************************

if _VERSION >= "Lua 5.2" then
  return _ENV
end
