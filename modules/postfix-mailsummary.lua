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

if maillist == nil then	-- protect against reloading
  maillist = {}		-- used to store loglines as they come in
end

-- ********************************************************************
--
-- postfix_mailsummary(msg)
--
-- Return true if the msg should be logged.  Otherwise, return false.
-- This will accumulate loglines from Postfix until there's enough
-- information (client, message-id, from, to) to log in a single line.
--
-- *********************************************************************

function postfix_mailsummary(msg)
  -- ==============================================================
  -- if we're not postfix logging to mail/info, exit early
  -- ==============================================================
  
  if string.find(msg.program,'postfix/',1,true) == nil then return true end
  if msg.facility ~= 'mail' then return true end
  if msg.level    ~= 'info' then return true end
  
  local email
  local id
  local data
  
  local function getemail(id)
    if maillist[id] == nil then
      maillist[id] = {}
    end
    return maillist[id]
  end

  if string.match(msg.msg,'^%S+%: client=.*') then
    id,data      = string.match(msg.msg,'^(%S+)%: client=(.*)$')
    if id == nil then
      return true
    end
    email        = getemail(id)
    email.client = data
    return false

  elseif string.match(msg.msg,'^%S+%: message%-id=.*') then
    id,data  = string.match(msg.msg,'^(%S+)%: message%-id=%<(%S+)%>')
    if id == nil then
      return true
    end
    email    = getemail(id)
    email.id = data
    return false

  elseif string.match(msg.msg,'^%S+%: from=.*') then
    id,data    = string.match(msg.msg,'^(%S+)%: from=%<(%S*)%>')
    if id == nil then
      return true
    end
    email      = getemail(id)
    email.from = data
    return false

  elseif string.match(msg.msg,'^%S+%: to=.*') then
    id,data  = string.match(msg.msg,'^(%S+)%: to=%<(%S+)%>')
    if id == nil then
      return true
    end
    email    = getemail(id)
    email.to = data
    return false

  elseif string.match(msg.msg,'^%S+%: removed') then
    id = string.match(msg.msg,'^(%S+)%:')
    
    if id == nil then
      return true
    end

    email = getemail(id)

    if email.client == nil then email.client = "(na)" end
    if email.from   == nil then email.from   = ""     end
    if email.to     == nil then email.to     = "(na)" end
    if email.id     == nil then email.id     = "<na>" end

    msg.program = 'summary/mail'
    msg.msg     = string.format(
    			"client=%s message-id=<%s> from=<%s> to=<%s>",
    			email.client,
    			email.id,
    			email.from,
    			email.to
    			)    	
    maillist[id] = nil
    return true
  end

  return false
end	
