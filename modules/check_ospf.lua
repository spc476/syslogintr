
require "template"
require "sendmail"

-- ********************************************************************

local recipients = 
{
  "spc@pickint.net",
  "admin@pickint.net"
}

local email_good = {}
      email_good.from          = "root@pickint.net"
      email_good.subject       = "Crisis over, OSPF up and running"
      email_good.body_template = [[

OSPF is back up and running, from %{host}%:

%{logmsg}%

Thanks.
]]

local email_bad = {}
      email_bad.from = "root@pickint.net"
      email_bad.subject = "EMERGENGY---OSPF Adjacency change!"
      email_bad.body_template = [[

We just received the following message from %{host}%:

%{logmsg}%

HELP!

]]

-- **********************************************************************

local function notify(to,email,msg)
  email.body = template(
	email.body_template,
	{ host = msg.host, logmsg = msg.msg }, 
	nil
  )

  for i = 1 , #to do
    email.to = to[i]
    send_email(email)
  end
end

-- ***********************************************************************

function check_ospf(msg)
  if string.match(msg.msg,".*(OSPF%-5%-ADJCHG.*Neighbor Down).*") then
    I_log("crit","OSPF neighbor down")
    notify(recipients,email_bad,msg)
  elseif string.match(msg.msg,".*(OSPF%-5%-ADJCHG.*LOADING to FULL).*") then
    I_log("crit","OSPF neighbor up")
    notify(recipients,email_good,msg)
  end
end
