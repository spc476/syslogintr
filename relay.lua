
homebase = host("lucy.roswell.conman.org")
if logfile == nil then
  logfile = io.open("/tmp/log","a")
end

function log(msg)
  logfile:write(string.format(
  		"%15.15s | %-25.25s | %-8s %6s | %s | %s\n",
  		msg.host,
  		msg.program,
  		msg.facility,
  		msg.level,
  		os.date("%c",msg.timestamp),
  		msg.msg
  	))
  logfile:flush()
  relay(homebase,msg)
end

