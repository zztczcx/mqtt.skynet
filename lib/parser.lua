local bit32 = require "bit32"
local constants = require "constants"

local parser = {}
local parser_mt = { __index = parser }

local packet = {}
function packet.new()
  return {
    cmd = nil,
    retain = false,
    qos = 0,
    dup = false,
    length = -1,
    topic = nil,
    payload = nil
  }
end

function parser.new()
  local self = {
    _buf = nil,
    packet = nil,
    _states = {
      '_parseHeader'
    , '_parseLength'
    , '_parsePayload'
    , '_newPacket'
    },
    _stateCounter = 1
  }

  return setmetatable(self, parser_mt)
end

function parser:_newPacket()
  if self.packet then
    self._buf = string.sub(self._buf, self.packet.length+1)
  end
  return true
end

function parser:parse(buf)
  self._buf = buf
  self.packet = packet.new()
  
  while ((string.len(self._buf) > 0) and --TODO test 去掉了packet.length 的判断
    self[self._states[self._stateCounter]](self) ) do

    self._stateCounter = self._stateCounter + 1

    if self._stateCounter > #self._states then
      self._stateCounter = 1
    end
  end
  return self.packet
end

function parser:_parseHeader()
  -- there is at least one byte in the buffer
  local zero = string.byte(self._buf)
  self.packet.cmd = constants.types[bit32.rshift(zero, constants.CMD_SHIFT)]
  self.packet.retain = (bit32.band(zero, constants.RETAIN_MASK)) ~= 0
  self.packet.qos = bit32.band(bit32.rshift(zero, constants.QOS_SHIFT), constants.QOS_MASK) 
  self.packet.dup = (bit32.band(zero, constants.DUP_MASK)) ~= 0

  self._buf = string.sub(self._buf, 2)

  return true
end

function parser:_parseLength()
  local bytes, mul, length, result = 1, 1, 0, true
  local current

  while bytes < 6 do
    current = string.byte(self._buf, bytes)
    bytes = bytes + 1

    length = length + mul * bit32.band(current, constants.LENGTH_MASK)
    mul = mul * 0x80

    if bit32.band(current, constants.LENGTH_FIN_MASK) == 0 then
      break
    end

    if string.len(self._buf) <= (bytes + 1) then -- TODO ?+1 check here maybe a bug
      result = false
      break
    end
  end

  if result then
    self.packet.length = length
    self._buf = string.sub(self._buf, bytes)
  end

  return result
end

function parser:_parsePayload() 
  local result = false

  -- Do we have a payload? Do we have enough data to complete the payload?
  -- PINGs have no payload
  if self.packet.length == 0 or string.len(self._buf) >= self.packet.length then
    self._pos = 1
    
    local cmd = self.packet.cmd
    if     cmd == 'connect'     then self:_parseConnect()
    elseif cmd == 'connack'     then self:_parseConnack()
    elseif cmd == 'publish'     then self:_parsePublish()
    elseif (cmd == 'puback' or cmd == 'pubrec' or cmd == 'pubrel' or cmd == 'pubcomp') then self:_parseMessageId()
    elseif cmd == 'subscribe'   then self:_parseSubscribe()
    elseif cmd == 'suback'      then self:_parseSuback()
    elseif cmd == 'unsubscribe' then self:_parseUnsubscribe()
    elseif cmd == 'unsuback'    then self:_parseUnsuback()
    elseif (cmd == 'pingreq' or cmd == 'pingresp' or cmd == 'disconnect') then
    else error("not supported")
    end

    result = true
  end

  return result
end

function parser:_parsePublish()
  local packet = self.packet
  packet.topic = self:_parseString()
  if packet.topic == nil then error("cannot parse topic") end

  if packet.qos > 0 then
    if not self:_parseMessageId() then
      return
    end
  end

  packet.payload = string.sub(self._buf, self._pos, packet.length)
end

function parser:_parseString()
  local length = self:_parseNum()
  local result

  if length == -1 or length + self._pos > string.len(self._buf) then
    return nil
  end

  result = string.sub(self._buf, self._pos, self._pos + length - 1)

  self._pos = self._pos + length
  return result
end

function parser:_parseNum()
  if 2 > self._pos + string.len(self._buf) then return -1 end

  local result = string.byte(self._buf) * 256 + string.byte(self._buf, 2) 
  self._pos = self._pos + 2 --TODO ? + 2

  return result
end


return parser
