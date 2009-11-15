-- ***************************************************************
--
-- Copyright 2009 by Sean Conner.  All Rights Reserved.
-- 
-- This program is free software; you can redistribute it and/or
-- modify it under the terms of the GNU General Public License
-- as published by the Free Software Foundation; either version 2
-- of the License, or (at your option) any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; if not, write to the Free Software
-- Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
--
-- Comments, questions and criticisms can be sent to: sean@conman.org
--
-- ********************************************************************

-- *****************************************************************
--
-- Program to print out each field and make sure we're parsing the
-- logs properly.  This is meant to be used from syslogintr as:
--
-- ./syslogintr --ipv4 --ipv6 --local --debug --foreground debug.lua
--
-- ******************************************************************

function log(msg)
  io.stdout:write(string.format("Request:\n"))
  io.stdout:write(string.format([[
	version      = %d
	_RAW         = %s
	host         = %s
	origin       = %s
	port         = %d
	remote       = %s
	timestamp    = %s
	logtimestamp = %s
	program      = %s
	pid          = %d
	facility     = %s
	level        = %s
	msg          = %s

]],
	msg.version,
	msg._RAW,
	msg.host,
	msg.origin,
	msg.port,
	tostring(msg.remote),
	os.date("%c",msg.timestamp),
	os.date("%c",msg.logtimestamp),
	msg.program,
	msg.pid,
	msg.facility,
	msg.level,
	msg.msg))
	
  io.stdout:flush()
end

	