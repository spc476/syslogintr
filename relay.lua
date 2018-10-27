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
--
-- A simple example of relaying logs to another host, as well as keeping
-- a local copy of each message.  The format for this local logfile isn't
-- standard, but it's a format I like that's easy to read.
--
-- **********************************************************************
-- luacheck: ignore 611
-- luacheck: globals relay host
-- luacheck: globals logfile log

local homebase = host("lucy.roswell.conman.org")
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

