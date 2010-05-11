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
-- Check OSPF messages from Cisco routers, and send an email whenever an
-- OSPF neighbor goes up or down.
--
-- check_ospf(msg,params)
--	msg 		-- syslog message as received
--	params 		-- optional parameters
--		params.from	-- From: address
--		params.to	-- To: address (can be an array)
--
-- *********************************************************************

require "template"
require "sendmail"

-- ********************************************************************

local email_good = {}
      email_good.subject       = "Crisis over, OSPF up and running"
      email_good.body_template = [[

OSPF is back up and running, from %{host}%:

%{logmsg}%

Thanks.
]]

local email_bad = {}
      email_bad.subject = "EMERGENGY---OSPF Adjacency change!"
      email_bad.body_template = [[

We just received the following message from %{host}%:

%{logmsg}%

HELP!

]]

-- **********************************************************************

local function notify(params,email,msg)
  send_email{
  	from = params.from or "root@conman.org",
  	to   = params.to   or "spc@conman.org",
  	subject = email.subject,
  	body    = template(
  			email.body_template,
  			{ host = msg.host , logmsg = msg.msg },
  			nil
  		)
  }  
end

-- ***********************************************************************

function check_ospf(msg,params) 
  if string.match(msg.msg,".*(OSPF%-5%-ADJCHG.*Neighbor Down).*") then
    I_log("crit","OSPF neighbor down")
    notify(params,email_bad,msg)
  elseif string.match(msg.msg,".*(OSPF%-5%-ADJCHG.*LOADING to FULL).*") then
    I_log("crit","OSPF neighbor up")
    notify(params,email_good,msg)
  end
end
