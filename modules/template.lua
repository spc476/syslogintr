
function template(text,callbacks,data)
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
