#!/usr/local/bin/lua

if #arg == 0 then
  scriptpath = "/usr/local/sbin/syslog.lua"
  script     = "syslog.lua"
else
  scriptpath = arg[1]
  script     = arg[2]
end

function alarm(time) end
function host(name) end

dofile(scriptpath)

g_hosts = 
{
  { host = "/dev/log"	, remote = false , port =  -1 } ,
--[[
  { host = "127.0.0.1"	, remote = true  , port = 514 } ,
  { host = ::1"		, remote = true  , port = 514 } ,
--]]
}

-- ***********************************************************************

function test_levels(msg)
  local levels = { 
  			"emerg" , "alert"  , "crit"  , "err" ,  
  			"warn"  , "notice" , "info"  , "debug" 
  		 }

  for i = 1 , #levels do
    msg.level = levels[i]
    log(msg)
  end
end

-- ************************************************************************

function test_facilities(msg)
  local facilities = {
  			"kernel" , "user"   , "mail"   , "daemon" ,
  			"auth1"  , "syslog" , "lpr"    , "news" , 
  			"uucp"   , "cron1"  , "auth2"  , "ftp" ,
  			"ntp"    , "auth3"  , "auth4"  , "cron2" ,
  			"local0" , "local1" , "local2" , "local3" ,
  			"local4" , "local5" , "local6" , "local7" }
  		     
  		      

  for i = 1 , #facilities do
    msg.facility = facilities[i]
    test_levels(msg)
  end
end

-- **************************************************************************

function test_hosts(msg)
  for i = 1 , #g_hosts do
    msg.remote = g_hosts[i].remote
    msg.host   = g_hosts[i].host
    msg.port   = g_hosts[i].port
    msg.relay  = g_hosts[i].host
    test_facilities(msg)
  end
end

-- ************************************************************************

function test_script()
  local msg = {}
  
  msg.version      = 0
  msg._RAW         = ""	-- not supported yet
  msg.timestamp    = os.time()
  msg.logtimestamp = os.time()
  msg.program      = "scripttester"
  msg.pid          = 0
  msg.msg          = "testing the script"
  
  test_hosts(msg)
end

-- **********************************************************************

test_script()
if cleanup ~= nil then cleanup() end
os.exit()
