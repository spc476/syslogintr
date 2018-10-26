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
-- Send an email.
--
-- send_email(email)
--
--      email           -- table with the following fields (all required):
--              email.from              -- From: address
--              email.to                -- To: address (can be an array)
--              email.subject           -- Subject: line
--              email.body              -- body of email
--
-- *********************************************************************

require "I_log"

local sendmail = "/usr/sbin/sendmail"

-- ************************************************************************

local function send_the_email(email)
  local exec = io.popen(sendmail .. " " .. email.to,"w")
  if exec == nil then
    I_log("crit","nonexec of sendmail")
    return
  end
  
  exec:write(string.format([[
From: %s
To: %s
Subject: %s
Date: %s

%s

]],
        email.from,
        email.to,
        email.subject,
        os.date("%a, %d %b %Y %H:%M:%S %Z",os.time()),
        email.body))
  exec:close()
  exec = nil
  
  I_log("debug","sent email to " .. email.to)
end

-- *********************************************************************

function send_email(email)
  if type(email.to) == 'table' then
    for i = 1 , #email.to do
      send_the_email{
        from    = email.from,
        to      = email.to[i],
        subject = email.subject,
        body    = email.body
      }
    end
  else
    send_the_email(email)
  end
end
