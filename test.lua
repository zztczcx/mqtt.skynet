package.path = package.path .. ';./lib/?.lua;'
local parser = require "parser"
local test_parser = parser.new()
local qublish_buffer = "\x30\x0a\x00\x04\x74\x65\x73\x74\x74\x65\x73\x74"
--connect = {
    --cmd: 'connect'
  --, retain: false
  --, qos: 0
  --, dup: false
  --, length: 18
  --, protocolId: 'MQIsdp'
  --, protocolVersion: 3
  --, clean: false
  --, keepalive: 30
  --, clientId: 'test'
--}
--local connect_buffer = "\x10\x12\x00\x06\x4d\x51\x49\x73\x64\x70\x03\x00\x00\x1e\x00\x04\x74\x65\x73\x74"
local connect_buffer = "\x10\x1b\x00\x06\x4d\x51\x49\x73\x64\x70\x03\xc4\x00\x1e\x00\x01\x74\x00\x01\x79\x00\x01\x64\x00\x01\x6d\x00\x01\x63"

local subscribe_buffer = "\x82\x09\x00\x2a\x00\x04\x74\x65\x73\x74\x00"

--local result = test_parser:parse(qublish_buffer)
--local result = test_parser:parse(connect_buffer)
local result = test_parser:parse(subscribe_buffer)

local inspect = require "inspect"
print(inspect(result))

