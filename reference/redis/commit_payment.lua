-- Atomic payment-accounting commit for the V4 reference architecture.
--
-- KEYS:
--   1 balances hash
--   2 paid hash
--   3 active intent string (JSON)
--   4 payments list
-- ARGV:
--   1 expected intent_id
--   2 payment journal JSON
--   3.. address, amount pairs

local raw = redis.call('GET', KEYS[3])
if not raw then
  return redis.error_reply('no active intent')
end

local ok, intent = pcall(cjson.decode, raw)
if not ok then
  return redis.error_reply('active intent is not valid JSON')
end
if intent['intent_id'] ~= ARGV[1] then
  return redis.error_reply('active intent id mismatch')
end
if intent['state'] ~= 'seen' then
  return redis.error_reply('active intent is not observed on chain/mempool')
end
if ((#ARGV - 2) % 2) ~= 0 then
  return redis.error_reply('address/amount arguments must be pairs')
end

for i = 3, #ARGV, 2 do
  local address = ARGV[i]
  local amount = tonumber(ARGV[i + 1])
  if (not amount) or amount <= 0 then
    return redis.error_reply('invalid payout amount')
  end
  local owed = tonumber(redis.call('HGET', KEYS[1], address) or '0')
  if owed < amount then
    return redis.error_reply('insufficient balance for ' .. address)
  end
end

for i = 3, #ARGV, 2 do
  local address = ARGV[i]
  local amount = tonumber(ARGV[i + 1])
  redis.call('HINCRBY', KEYS[1], address, -amount)
  redis.call('HINCRBY', KEYS[2], address, amount)
end

redis.call('LPUSH', KEYS[4], ARGV[2])
redis.call('DEL', KEYS[3])
return 'COMMITTED'
