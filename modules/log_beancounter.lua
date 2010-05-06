
require "I_log"

function log_bean()
  local uid
  local resource
  local held
  local maxheld
  local barrier
  local limit
  local failcnt
  local line
  local file = io.open("/proc/user_beancounters","r")

  line = file:read("*l") -- burn Version line
  line = file:read("*l") -- burn header line
  line = file:read("*l") -- first line of read input

  uid,resource,held,maxheld,barrier,limit,failcnt = line:match("^%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)")
  if tonumber(failcnt) > 0 then
    I_prlog("check/beancounters","notice",string.format("%s h=%s m=%s b=%s l=%s f=%s\n",resource,held,maxheld,barrier,limit,failcnt))
  end

  for line in file:lines() do
    resource,held,maxheld,barrier,limit,failcnt = line:match("^%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)%s+(%S+)")
    if tonumber(failcnt) > 0 then
      I_prlog("check/beancounters","notice",string.format("%s h=%s m=%s b=%s l=%s f=%s\n",resource,held,maxheld,barrier,limit,failcnt))
    end
  end
  file:close()
end
