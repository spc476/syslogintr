
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
