
function log(msg)

  if msg.remote then
    io.stdout:write(string.format("From: %15s:%d\n",msg.host,msg.port))
  else
    io.stdout:write(string.format("From: %15s\n",msg.host))
  end

  io.stdout:write(string.format([[
	Facility: %s
	Level:    %s
	Time:     %s
	Log-time: %s
	Program:  %s
	PID:      %s
	Msg:      %s
	
]],
	msg.facility,
	msg.level,
	os.date("%c",msg.timestamp),
	os.date("%c",msg.logtimestatmp),
	msg.program,
	msg.pid,
	msg.msg
  ))

end
