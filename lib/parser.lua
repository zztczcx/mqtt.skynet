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

    if string.len(self._buf) < bytes then
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


function parser:_parseConnect()
  local protocolId -- constants id
  local clientId --Client id
  local topic  --Will topic
  local payload -- Will payload
  local password -- Password
  local username -- Username
  local flags = {}
  local packet = self.packet

  protocolId = self:_parseString()
  if protocolId == nil then
    return error('cannot parse protocol id')
  end

  packet.protocolId = protocolId

  -- Parse constants version number
  if self._pos > string.len(self._buf) then
    return error('packet too short')
  end

  packet.protocolVersion = string.byte(self._buf, self._pos)
  self._pos = self._pos + 1

  flags.username = bit32.band(string.byte(self._buf, self._pos), constants.USERNAME_MASK)
  flags.password = bit32.band(string.byte(self._buf, self._pos), constants.PASSWORD_MASK)
  flags.will     = bit32.band(string.byte(self._buf, self._pos), constants.WILL_FLAG_MASK)

  if flags.will ~= 0 then
    packet.will = {}
    packet.will.retain = bit32.band(string.byte(self._buf, self._pos), constants.WILL_RETAIN_MASK) ~= 0

    packet.will.qos    = bit32.rshift(bit32.band(string.byte(self._buf, self._pos), constants.WILL_QOS_MASK), constants.WILL_QOS_SHIFT)
  end

  packet.clean  = bit32.band(string.byte(self._buf, self._pos), constants.CLEAN_SESSION_MASK) ~= 0
  self._pos = self._pos + 1

  -- Parse keepalive
  packet.keepalive = self:_parseNum()
  if packet.keepalive == -1 then
    error('packet too short')
  end

  --Parse client ID
  clientId = self:_parseString()
  if clientId == nil then
    error('pakcet too short')
  end
  packet.clientId = clientId

  if flags.will ~= 0 then
    -- Parse will topic
    topic = self:_parseString()
    if topic == nil then
      error('cannot parse will topic')
    end
    packet.will.topic = topic

    -- Parse will payload
    payload = self:_parseBuffer()
    if payload == nil then
      error('cannot parse will payload')
    end
    packet.will.payload = payload

    -- Parse username
    if flags.username then
      username = self:_parseString()
      if username == nil then
        error('cannot parse username')
      end
      packet.username = username
    end

    -- Parse password
    if flags.password then
      password = self:_parseBuffer()
      if password == nil then
        error('cannot parse username')
      end
      packet.password = password
    end

    return packet
  end

end


function parser:_parseConnack()
  local packet = self.packet
  packet.sessionPresend = not not bit32.band(string.byte(self._buf, self._pos), constants.SESSIONPRESENT_MASK)

  self._pos = self._pos + 1

  packet.returnCode = string.byte(self._buf, self._pos)
  if packet.returnCode == -1 then
    error('canno parse return code')
  end
end


function parser:_parsePublish()
  local packet = self.packet
  packet.topic = self:_parseString()

  if packet.topic == nil then 
    error("cannot parse topic") 
  end

  if packet.qos > 0 then
    if not self:_parseMessageId() then
      return
    end
  end

  packet.payload = string.sub(self._buf, self._pos, packet.length)
end


function parser:_parseSubscribe()
  local packet = self.packet
  local topic, qos

  if packet.qos ~= 1 then
    error('wrong subscribe header')
  end

  packet.subscriptions = {}

  if not self:_parseMessageId() then return end
  while self._pos <= packet.length do
    -- Parse topic
    topic = self:_parseString()
    if topic == nil then 
      error('Parse error - cannot parse topic')
    end

    qos = string.byte(self._buf, self._pos)
    self._pos = self._pos + 1

    table.insert(packet.subscriptions, {topic=topic, qos=qos})
  end
end


function parser:_parseMessageId()
  local packet = self.packet
  packet.messageId = self:_parseNum()

  if packet.messageId == nil then
    error('cannot parse message id')
  end

  return true
end


function parser:_parseString()
  local length = self:_parseNum()
  local result

  if length == -1 or length + self._pos - 1 > string.len(self._buf) then
    return nil
  end

  result = string.sub(self._buf, self._pos, self._pos + length - 1)

  self._pos = self._pos + length
  return result
end


function parser:_parseBuffer()
  local length = self:_parseNum()
  local result

  if length == -1 or length + self._pos - 1 > string.len(self._buf) then
    return nil
  end

  result = string.sub(self._buf, self._pos, self._pos + length - 1)
  self._pos = self._pos + length

  return result
end


function parser:_parseNum()
  if 2 > self._pos + string.len(self._buf) then return -1 end

  local result = string.byte(self._buf, self._pos) * 256 + string.byte(self._buf, self._pos + 1) 
  self._pos = self._pos + 2 

  return result
end


return parser
