
require "I_log"

local sendmail = "/usr/sbin/sendmail"

-- ************************************************************************

function send_email(email)
{
  local sendmail = io.popen(sendmail .. " " .. email.to,"w")
  if sendmail == nil then
    I_log("crit","nonexec of sendmail")
    return
  end
  
  sendmail:write(string.format([[
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
  sendmail:close()
  I_log("debug","send email")
end
  
