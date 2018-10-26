
-- luacheck: globals log
-- luacheck: ignore 611

local math = require "math"
local tty  = require "org.flummux.tty"

local levels =
{
  emerg  = { x =  1 , y = 1 , count = 0 , color = "\27[1;31m" },
  alert  = { x = 11 , y = 1 , count = 0 , color = "\27[0;31m" },
  crit   = { x = 21 , y = 1 , count = 0 , color = "\27[0;31m" },
  err    = { x = 31 , y = 1 , count = 0 , color = "\27[0;31m" },
  warn   = { x = 41 , y = 1 , count = 0 , color = "\27[1;33m" },
  notice = { x = 51 , y = 1 , count = 0 , color = "\27[1;32m" },
  info   = { x = 61 , y = 1 , count = 0 , color = "\27[0;32m" },
  debug  = { x = 71 , y = 1 , count = 0 , color = "\27[1;34m" },
}

local facilities =
{
  kernel = { x =  1 , y = 4 , count = 0 , lcolor = "\27[1;37m" , color = "\27[0;37m" },
  user   = { x = 11 , y = 4 , count = 0 , lcolor = "\27[1;37m" , color = "\27[0;37m" },
  mail   = { x = 21 , y = 4 , count = 0 , lcolor = "\27[1;37m" , color = "\27[0;37m" },
  daemon = { x = 31 , y = 4 , count = 0 , lcolor = "\27[1;37m" , color = "\27[0;37m" },
  auth1  = { x = 41 , y = 4 , count = 0 , lcolor = "\27[1;37m" , color = "\27[0;37m" },
  syslog = { x = 51 , y = 4 , count = 0 , lcolor = "\27[1;37m" , color = "\27[0;37m" },
  lpr    = { x = 61 , y = 4 , count = 0 , lcolor = "\27[1;37m" , color = "\27[0;37m" },
  news   = { x = 71 , y = 4 , count = 0 , lcolor = "\27[1;37m" , color = "\27[0;37m" },
  uucp   = { x =  1 , y = 6 , count = 0 , lcolor = "\27[1;37m" , color = "\27[0;37m" },
  cron1  = { x = 11 , y = 6 , count = 0 , lcolor = "\27[1;37m" , color = "\27[0;37m" },
  auth2  = { x = 21 , y = 6 , count = 0 , lcolor = "\27[1;37m" , color = "\27[0;37m" },
  ftp    = { x = 31 , y = 6 , count = 0 , lcolor = "\27[1;37m" , color = "\27[0;37m" },
  ntp    = { x = 41 , y = 6 , count = 0 , lcolor = "\27[1;37m" , color = "\27[0;37m" },
  auth3  = { x = 51 , y = 6 , count = 0 , lcolor = "\27[1;37m" , color = "\27[0;37m" },
  auth4  = { x = 61 , y = 6 , count = 0 , lcolor = "\27[1;37m" , color = "\27[0;37m" },
  cron2  = { x = 71 , y = 6 , count = 0 , lcolor = "\27[1;37m" , color = "\27[0;37m" },
  local0 = { x =  1 , y = 8 , count = 0 , lcolor = "\27[1;37m" , color = "\27[0;37m" },
  local1 = { x = 11 , y = 8 , count = 0 , lcolor = "\27[1;37m" , color = "\27[0;37m" },
  local2 = { x = 21 , y = 8 , count = 0 , lcolor = "\27[1;37m" , color = "\27[0;37m" },
  local3 = { x = 31 , y = 8 , count = 0 , lcolor = "\27[1;37m" , color = "\27[0;37m" },
  local4 = { x = 41 , y = 8 , count = 0 , lcolor = "\27[1;37m" , color = "\27[0;37m" },
  local5 = { x = 51 , y = 8 , count = 0 , lcolor = "\27[1;37m" , color = "\27[0;37m" },
  local6 = { x = 61 , y = 8 , count = 0 , lcolor = "\27[1;37m" , color = "\27[0;37m" },
  local7 = { x = 71 , y = 8 , count = 0 , lcolor = "\27[1;37m" , color = "\27[0;37m" },
}

local msgs =
{
  emerg  = { x = 1 , y = 11 , color = "\27[1;31m" , host = "-" , msg = "-" },
  alert  = { x = 1 , y = 12 , color = "\27[0;31m" , host = "-" , msg = "-" },
  crit   = { x = 1 , y = 13 , color = "\27[0;31m" , host = "-" , msg = "-" },
  err    = { x = 1 , y = 14 , color = "\27[0;31m" , host = "-" , msg = "-" },
  warn   = { x = 1 , y = 15 , color = "\27[1;33m" , host = "-" , msg = "-" },
  notice = { x = 1 , y = 16 , color = "\27[1;32m" , host = "-" , msg = "-" },
  info   = { x = 1 , y = 17 , color = "\27[0;32m" , host = "-" , msg = "-" },
  debug  = { x = 1 , y = 18 , color = "\27[1;34m" , host = "-" , msg = "-" },
}

local hosts     = setmetatable({},{ __index = function() return 0 end })
local msgcount  = 0
local hostcount = 0
local zen       = os.time()

tty.open()
tty.clear_screen()
tty.cursor_off()

for level,info in pairs(levels) do
  tty.move(info.x,info.y)
  tty.write(info.color,string.format("%10s",level))
  tty.move(info.x,info.y + 1)
  tty.write(string.format("%10s",'-'))
end

for facility,info in pairs(facilities) do
  tty.move(info.x,info.y)
  tty.write(info.lcolor,string.format("%10s",facility))
  tty.move(info.x,info.y + 1)
  tty.write(info.color,string.format("%10s",'-'))
end

for _,msg in pairs(msgs) do
  tty.move(msg.x,msg.y)
  tty.write(msg.color,string.format("%15s %-64.64s",msg.host,msg.msg))
end

function log(msg)
  msgcount = msgcount + 1
  
  local level    = levels[msg.level]
  local facility = facilities[msg.facility]
  local text     = msgs[msg.level]
  
  hosts[msg.host] = hosts[msg.host] + 1
  
  level.count    = level.count + 1
  facility.count = facility.count + 1
  text.host      = msg.host
  text.msg       = msg.msg
  
  tty.move(level.x,level.y + 1)
  tty.write(level.color,string.format(" %9d",level.count))
  
  tty.move(facility.x,facility.y + 1)
  tty.write(facility.color,string.format(" %9d",facility.count))
  
  tty.move(text.x,text.y)
  tty.write("\27[K")
  tty.write(text.color,string.format("%15s %-64.64s",text.host,text.msg))
  
  local list = {}
  for host,count in pairs(hosts) do
    table.insert(list,{ host = host,count = count })
  end
  
  hostcount = #list
  
  table.sort(list,function(a,b) return a.count > b.count end)
  
  local x,y = 1 , 20
  for i = 1 , math.min(#list,10) do
    tty.move(x,y)
    tty.write(string.format(" \27[1;37m%15s",list[i].host))
    tty.move(x,y+1)
    tty.write(string.format(" \27[0;37m%15d",list[i].count))
    x = x + 16
    if x == 81 then
      x = 1
      y = y + 2
    end
  end
  
  local timedelta do
    local tao   = os.time()
    local delta = os.difftime(tao,zen)
    local days  = math.floor(delta / 86400) delta = delta % 86400
    local hours = math.floor(delta /  3600) delta = delta %  3600
    local mins  = math.floor(delta /    60)
    
    if days > 0 then days = string.format("%3dd",days) else days = "   " end
    timedelta = string.format("%s %02d:%02d",days,hours,mins)
  end
  
  tty.move(1,24)
  tty.write(string.format("\27[1;37mMessages: \27[0;37m%-9d \27[1;37mHosts: \27[0;37m%-3d \27[1;37mMemory: \27[0;37m%-9d \27[1;37mTime: \27[0;37m%s", -- luacheck: ignore
        msgcount,
        hostcount,
        collectgarbage('count') * 1024,
        timedelta
  ))
end

--[[
log { level = "emerg"  , facility = "local1" , host = "192.168.1.10" , msg = "test" }
log { level = "alert"  , facility = "local1" , host = "192.168.1.11" , msg = "test" }
log { level = "crit"   , facility = "local1" , host = "192.168.1.12" , msg = "test" }
log { level = "err"    , facility = "local1" , host = "192.168.1.13" , msg = "test" }
log { level = "warn"   , facility = "local1" , host = "192.168.1.14" , msg = "test" }
log { level = "notice" , facility = "local1" , host = "192.168.1.15" , msg = "test" }
log { level = "info"   , facility = "local1" , host = "192.168.1.16" , msg = "test" }
log { level = "debug"  , facility = "local1" , host = "192.168.1.17" , msg = "test" }

log { level = "emerg"  , facility = "local1" , host = "192.168.1.15" , msg = "test" }
log { level = "alert"  , facility = "local1" , host = "192.168.1.15" , msg = "test" }
log { level = "crit"   , facility = "local1" , host = "192.168.1.15" , msg = "test" }
log { level = "err"    , facility = "local1" , host = "192.168.1.11" , msg = "test" }
log { level = "warn"   , facility = "local1" , host = "192.168.1.11" , msg = "test" }
log { level = "notice" , facility = "local1" , host = "192.168.1.11" , msg = "test" }
log { level = "info"   , facility = "local1" , host = "192.168.1.15" , msg = "test" }
log { level = "debug"  , facility = "local1" , host = "192.168.1.11" , msg = "test" }

tty.readchar()
--]]
