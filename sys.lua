-- ***************************************************************
--
-- Copyright 2010 by Sean Conner.  All Rights Reserved.
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program.  If not, see <http://www.gnu.org/licenses/>.
--
-- Comments, questions and criticisms can be sent to: sean@conman.org
--
-- ********************************************************************
-- luacheck: ignore 611
-- luacheck: globals log

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
