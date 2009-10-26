
function log(msg)
  io.stdout:write(string.format(
  		"%15.15s | %-25.25s | %-8s %6s | %s | %s\n",
  		msg.host,
  		msg.program,
  		msg.facility,
  		msg.level,
  		os.date("%c",msg.timestamp),
  		msg.msg
  	))
end
