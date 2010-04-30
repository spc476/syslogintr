


-- cut -b 1-187 (to account for XTERM escape sequences)

io.stdout:write("\27[2J")	-- clear screen to black
io.stdout:flush()

colors =
{
  emerg  = "\27[1;31m",
  alert  = "\27[0;31m",
  crit   = "\27[0;31m",
  err    = "\27[0;31m",
  warn   = "\27[0;33m",
  notice = "\27[1;32m",
  info   = "\27[0;32m",
  debug  = "\27[0;34m"
}

function log(msg)
  io.stdout:write(string.format(
	"%s%15.15s | %-15.15s | %-8s %6s | %s | %s\n",
	colors[msg.level],
	msg.host,
	msg.program,
	msg.facility,
	msg.level,
	os.date("%b %d %H:%M:%S",msg.timestamp),
	msg.msg
	))
  io.stdout:flush()
end
