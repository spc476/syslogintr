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
-- Postfix logs several messages per email (thin logging).  This module
-- will collect those messages and once all the logs for an individual
-- email have been collected, a summary (fat logging) is generated.
--
-- *********************************************************************
-- luacheck: ignore 611
-- luacheck: globals maillist

if maillist == nil then -- protect against reloading
  maillist = {}         -- used to store loglines as they come in
end

-- ********************************************************************
--
-- postfix_mailsummary(msg)
--
-- Return a new msg if the msg should be logged.  Otherwise, return false.
-- This will accumulate loglines from Postfix until there's enough
-- information (client, message-id, from, to) to log in a single line.
--
-- *********************************************************************

return function(msg)
  -- ==============================================================
  -- if we're not postfix logging to mail/info, exit early
  -- ==============================================================
  
  if string.find(msg.program,'postfix/',1,true) == nil then return false end
  if msg.facility ~= 'mail' then return false end
  if msg.level    ~= 'info' then return false end
  
  local function getemail(key)
    if maillist[key] == nil then
      maillist[key] = {}
    end
    return maillist[key]
  end
  
  if string.match(msg.msg,'^%S+%: client=.*') then
    local id,data = string.match(msg.msg,'^(%S+)%: client=(.*)$')
    if id then
      local email  = getemail(id)
      email.client = data
    end
    
  elseif string.match(msg.msg,'^%S+%: message%-id=.*') then
    local id,data = string.match(msg.msg,'^(%S+)%: message%-id=%<(%S+)%>')
    if id then
      local email = getemail(id)
      email.id    = data
    end
    
  elseif string.match(msg.msg,'^%S+%: from=.*') then
    local id,data = string.match(msg.msg,'^(%S+)%: from=%<(%S*)%>')
    if id then
      local email = getemail(id)
      email.from  = data
    end
    
  elseif string.match(msg.msg,'^%S+%: to=.*') then
    local id,data = string.match(msg.msg,'^(%S+)%: to=%<(%S+)%>')
    if id then
      local email = getemail(id)
      email.to    = data
    end
    
  elseif string.match(msg.msg,'^%S+%: removed') then
    local id = string.match(msg.msg,'^(%S+)%:')
    if id then
      local email  = getemail(id)
      maillist[id] = nil
      
      return {
        version   = msg.version,
        facility  = msg.facility,
        level     = msg.level,
        timestamp = os.time(),
        pid       = msg.pid,
        host      = msg.host,
        relay     = msg.relay,
        port      = msg.port,
        localaddr = msg.localaddr,
        localport = msg.localport,
        program   = "summary/mail",
        msg       = string.format(
                      "client=%s message-id=<%s> from=<%s> to=<%s>",
                      email.client or "-",
                      email.id     or "<>",
                      email.from   or "<>",
                      email.to     or "<>"
                    ),
      }
    end
  end
  
  return false
end
