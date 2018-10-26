-- ***************************************************************
--
-- Copyright 2009 by Sean Conner.  All Rights Reserved.
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
-- delta_time(diff)
--
-- Returns a string that represents the output from os.difftime()
--
-- ******************************************************************

function delta_time(diff)

  if diff == 0 then return "0s" end
  
  local SECSMIN  = 60.0
  local SECSHOUR = SECSMIN  * 60.0
  local SECSDAY  = SECSHOUR * 24.0
  local SECSYEAR = SECSDAY  * 365.242199
  
  local year = math.floor(diff / SECSYEAR) diff = diff - (year * SECSYEAR)
  local day  = math.floor(diff / SECSDAY)  diff = diff - (day  * SECSDAY)
  local hour = math.floor(diff / SECSHOUR) diff = diff - (hour * SECSHOUR)
  local min  = math.floor(diff / SECSMIN)  diff = diff - (min  * SECSMIN)
  local sec  = math.floor(diff)
  local out  = ""
  
  if year ~= 0 then out = out .. string.format("%dy",year)  end
  if day  ~= 0 then out = out .. string.format("_%dd",day)  end
  if hour ~= 0 then out = out .. string.format("_%dh",hour) end
  if min  ~= 0 then out = out .. string.format("_%dm",min)  end
  if sec  ~= 0 then out = out .. string.format("_%ds",sec)  end
  
  return out
end

