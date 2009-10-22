
function log(msg)
  io.stdout:write(string.format(
  		"%15.15s | %-8s %6s | %-20.20s | %s | %s\n",
  		msg.host,
  		msg.facility,
  		msg.level,
  		msg.program,
  		os.date("%c",msg.timestamp),
  		msg.msg
  	))
end
