package.path = package.path .. ';../lib/?.lua;'
local parser = require "parser"
local test_parser = parser.new()
local max = 1000000
local i
local start
local time = os.clock()

local buffer = "\x30\x0a\x00\x04\x74\x65\x73\x74\x74\x65\x73\x74"

for i=1, max do
  test_parser:parse(buffer)
end

time = os.clock() - time
print('Total packets', max)
print('Total time', time)
print('Packet/s', max / time)
