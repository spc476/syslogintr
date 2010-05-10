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

-- *******************************************************************
--
-- function to locally log syslog-esque messages.
--
-- Beware of logging loops though.
--
-- *******************************************************************

function I_prlog(program,level,msg)
  log{
  	host      = "(internal)",
  	remote    = false,
  	program   = program,
	pid       = 0,
  	facility  = "syslog",
  	level     = level,
  	timestamp = os.time(),
  	msg       = msg
  }
end

-- *******************************************************************

function I_log(level,msg)
  I_prlog(script,level,msg)
end

