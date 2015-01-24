local constants = {}
constants.types = {
  [0] = 'reserved',
  [1] = 'connect',
  [2] = 'connack',
  [3] = 'publish',
  [4] = 'puback',
  [5] = 'pubrec',
  [6] = 'pubrel',
  [7] = 'pubcomp',
  [8] = 'subscribe',
  [9] = 'suback',
  [10] = 'unsubscribe',
  [11] = 'unsuback',
  [12] = 'pingreq',
  [13] = 'pingresp',
  [14] = 'disconnect',
  [15] = 'reserved'
}

--TODO 0 的索引问题
-- Mnemonic => Command code
constants.codes = {}
for k, v in ipairs(constants.types) do
  constants.codes[v] = k
end

constants.CMD_SHIFT = 4;
constants.CMD_MASK = 0xF0;
constants.DUP_MASK = 0x08;
constants.QOS_MASK = 0x03;
constants.QOS_SHIFT = 1;
constants.RETAIN_MASK = 0x01;

-- Length
constants.LENGTH_MASK = 0x7F;
constants.LENGTH_FIN_MASK = 0x80;

-- Connack 
constants.SESSIONPRESENT_MASK = 0x01;

-- Connect 
constants.USERNAME_MASK = 0x80;
constants.PASSWORD_MASK = 0x40;
constants.WILL_RETAIN_MASK = 0x20;
constants.WILL_QOS_MASK = 0x18;
constants.WILL_QOS_SHIFT = 3;
constants.WILL_FLAG_MASK = 0x04;
constants.CLEAN_SESSION_MASK = 0x02;

return constants
