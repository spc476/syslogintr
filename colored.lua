

-- cut -b 1-187 (to account for XTERM escape sequences)
--io.stdout:write("\27[2J")	-- clear screen to black
--io.stdout:flush()

--[[
if logfiles == nil then
  logfiles = {}
  logfiles = setmetatable({},{
  	__index = function(t,k)
  	  local fname = "/tmp/logs/" .. k
  	  t[k] = io.open(fname,"a")
  	  return t[k]
  	end
  	})
end
--]]

colors =
{
  emerg  = "\27[1;31m",
  alert  = "\27[0;31m",
  crit   = "\27[0;31m",
  err    = "\27[0;31m",
  warn   = "\27[0;33m",
  notice = "\27[1;32m",
  info   = "\27[0;32m",
  debug  = "\27[1;34m"
}

function log(msg)
  io.stdout:write(string.format(
	"%s%15.15s %-15.15s %-6s %6s %s %s\n",
	colors[msg.level],
	msg.host,
	msg.program,
	msg.facility,
	msg.level,
	os.date("%b %d %H:%M:%S",msg.timestamp),
	msg.msg
	))
  io.stdout:flush()
  
  --logfiles[msg.host]:write(string.format("%s\n",msg._RAW))
  --logfiles[msg.host]:flush()
end
