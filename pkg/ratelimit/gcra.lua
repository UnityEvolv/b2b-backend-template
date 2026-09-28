-- GCRA: `limit` requests per `window_ms`, refilled smoothly, bursts of up to
-- `limit` allowed. One key per bucket holding the theoretical arrival time.
-- Atomic, and on Redis's clock, so every node sees the same answer.
--
-- Shared, byte for byte, by the Go services (pkg/ratelimit) and the realtime
-- service (services/realtime/src/gcra.lua). internal/repocheck fails if the
-- two copies differ.
--
-- KEYS[1]  the bucket
-- ARGV[1]  limit      requests per window
-- ARGV[2]  window_ms  the window
-- ARGV[3]  cost       0 checks without spending; 1 spends one request
--
-- Returns { allowed (0|1), remaining, retry_after_ms }.

local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local cost = tonumber(ARGV[3])

local clock = redis.call('TIME')
local now = tonumber(clock[1]) * 1000 + math.floor(tonumber(clock[2]) / 1000)

local interval = window / limit
local tat = tonumber(redis.call('GET', KEYS[1])) or now
if tat < now then
  tat = now
end

-- Would one more request fit? A check (cost 0) asks the same question as a
-- spend; it just does not record the answer.
local probe = tat + interval * math.max(cost, 1)
local allow_at = probe - window
if allow_at > now then
  return { 0, 0, math.ceil(allow_at - now) }
end

if cost > 0 then
  local new_tat = tat + interval * cost
  redis.call('SET', KEYS[1], tostring(new_tat), 'PX', math.ceil(new_tat - now))
end
local remaining = math.floor((window - (probe - now)) / interval)
return { 1, remaining, 0 }
