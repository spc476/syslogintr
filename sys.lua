
function main(log)

  if log.remote then
    io.stdout:write(string.format("From: %15s:%d\n",log.host,log.port))
  else
    io.stdout:write(string.format("From: %15s\n",log.host))
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
	log.facility,
	log.level,
	os.date("%c",log.timestamp),
	os.date("%c",log.logtimestatmp),
	log.program,
	log.pid,
	log.msg
  ))

end
