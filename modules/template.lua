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
-- A simple template processor.
--
-- template(text,callbacks,data)
--
--      text            -- string that is the template
--      callbacks       -- replacement values
--      data            -- block (not touched by template()) that can be used
--                         for user specific data
--
-- Example usage:
--      body = "Hello %{name}%, you have called %{times}% times."
--      callbacks =
--      {
--              name = "Sean Conner",
--              times = function(data) return tostring(data) end
--      }
--      times_called = 1
--
--      print(template(body,callbacks,times_called))
--
-- **********************************************************************
-- luacheck: ignore 611

return function(text,callbacks,data)
  local function cmd(tag)
    local word = string.sub(tag,3,-3)
    
    if type(callbacks[word]) == "string" then
      return callbacks[word]
    elseif type(callbacks[word]) == "function" then
      return callbacks[word](data)
    else
      return tostring(callbacks[word])
    end
  end
  
  local s = string.gsub(text,"%%{[%w%.]+}%%",cmd)
  return s
end
