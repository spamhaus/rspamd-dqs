--------------------------------------------------------------------------------
-- util functions, thanks to https://github.com/aiq/basexx
--------------------------------------------------------------------------------

local function divide_string( str, max )
   local result = {}

   local start = 1
   for i = 1, #str do
      if i % max == 0 then
         table.insert( result, str:sub( start, i ) )
         start = i + 1
      elseif i == #str then
         table.insert( result, str:sub( start, i ) )
      end
   end

   return result
end

local basexx = {}

local bitMap = { o = "0", i = "1", l = "1" }

function basexx.to_bit( str )
   return ( str:gsub( '.', function ( c )
               local byte = string.byte( c )
               local bits = {}
               for _ = 1,8 do
                  table.insert( bits, byte % 2 )
                  byte = math.floor( byte / 2 )
               end
               return table.concat( bits ):reverse()
            end ) )
end

local function to_basexx( str, alphabet, bits, pad )
   local bitString = basexx.to_bit( str )

   local chunks = divide_string( bitString, bits )
   local result = {}
   for _,value in ipairs( chunks ) do
      if ( #value < bits ) then
          value = value .. string.rep( '0', bits - #value )
      end
      local pos = tonumber( value, 2 ) + 1
      table.insert( result, alphabet:sub( pos, pos ) )
   end

   table.insert( result, pad )
   return table.concat( result )
end

local base32Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
local base32PadMap = { "" }

function basexx.to_base32( str )
    return to_basexx( str, base32Alphabet, 5, base32PadMap[ #str % 5 + 1 ] )
end

--------------------------------------------------------------------------------

local rspamd_logger = require "rspamd_logger"
local rspamd_re = require "rspamd_regexp"
local rspamd_hash = require "rspamd_cryptobox_hash"
local rspamd_util = require "rspamd_util"

local check_cw_dns = '._cw.your_DQS_key.hbl.dq.spamhaus.net.'
local check_file_dns = '._file.your_DQS_key.hbl.dq.spamhaus.net.'

local function check_cw_callback ( task, re, lowercase, cryptovalue )
    local parts = task:get_text_parts()
    if not parts then return false end
    local r = task:get_resolver()
    for _, part in ipairs(parts) do
        local words = part:get_words('raw')
        for _, word in ipairs(words) do
        if (lowercase == 1) then word = string.lower(word) end
            local match = re:match(word)
            if match then
                local hash = rspamd_hash.create_specific('sha1', word):hex()
                rspamd_logger.infox('HASH ' .. hash)
        local lookup = hash .. check_cw_dns
        local function dns_cb(_,_,results,err)
            if (not results) then return false end
            if (string.find(tostring(results[1]), '127.0.')) then
                        rspamd_logger.infox('found ' .. cryptovalue .. ' wallet %s (hashed: %s) in Cryptowallet blacklist', word, hash)
                        return task:insert_result('RBL_SPAMHAUS_CW_' .. cryptovalue, 1.0, word);
                    end
                end
                r:resolve_a({ task = task, name = lookup , callback = dns_cb, forced = true })
            end
        end
    end
end

local function check_file_callback ( task, ret, type )
    local parts = task:get_parts()
    if not parts then return false end
    local r = task:get_resolver()
    for _,p in ipairs(parts) do
    local ct = p:get_content()
    local filehash = basexx.to_base32(rspamd_hash.create_specific('sha256', ct):bin())
    local lookup = filehash .. check_file_dns
    local function dns_cb(_,_,results,err)
        if (not results) then return false end
        if (string.find(tostring(results[1]), ret)) then
                rspamd_logger.infox('Attachment hash %s found in Spamhaus Malware HASHBL_' .. type , rspamd_hash.create_specific('sha256', ct):hex())
                return task:insert_result('RBL_SPAMHAUS_' .. type, 1.0, word);
             end
         end
         r:resolve_a({ task = task, name = lookup , callback = dns_cb, forced = true })
    end
end

rspamd_config:register_symbol({
    name = "RBL_SPAMHAUS_CW_BTC",
    score = 7.0,
    description = "BTC found in Spamhaus cryptowallet list",
    group = "spamhaus",
    type = "callback",
    callback = function(task)
        -- BTC regex
        local re = rspamd_re.create_cached('^(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$')
        local lowercase = 0
        local cryptovalue = "BTC"
        check_cw_callback (task, re, lowercase, cryptovalue )
    end
})

rspamd_config:register_symbol({
    name = "RBL_SPAMHAUS_CW_ETH",
    score = 7.0,
    description = "ETH found in Spamhaus cryptowallet list",
    group = "spamhaus",
    type = "callback",
    callback = function(task)
        -- ETH regex
        local re = rspamd_re.create_cached('^0x[a-fA-F0-9]{40}$')
        local lowercase = 1
        local cryptovalue = "ETH"
        check_cw_callback (task, re, lowercase, cryptovalue )
    end
})

rspamd_config:register_symbol({
    name = "RBL_SPAMHAUS_CW_BCH",
    score = 7.0,
    description = "BCH found in Spamhaus cryptowallet list",
    group = "spamhaus",
    type = "callback",
    callback = function(task)
        -- BCH regex
        local re = rspamd_re.create_cached('(?<!=)bitcoincash:(?:q|p)[a-z0-9]{41}')
        local lowercase = 0
        local cryptovalue = "BCH"
        check_cw_callback (task, re, lowercase, cryptovalue )
    end
})

rspamd_config:register_symbol({
    name = "RBL_SPAMHAUS_CW_XMR",
    score = 7.0,
    description = "XMR found in Spamhaus cryptowallet list",
    group = "spamhaus",
    type = "callback",
    callback = function(task)
        -- XMR regex
        local re = rspamd_re.create_cached('^(?:4(?:[0-9]|[A-B])(?:.){93})$')
        local lowercase = 0
        local cryptovalue = "XMR"
        check_cw_callback (task, re, lowercase, cryptovalue )
    end
})

rspamd_config:register_symbol({
    name = "RBL_SPAMHAUS_CW_LTC",
    score = 7.0,
    description = "LTC found in Spamhaus cryptowallet list",
    group = "spamhaus",
    type = "callback",
    callback = function(task)
        -- LTC regex
        local re = rspamd_re.create_cached('^(?:[LM3][a-km-zA-HJ-NP-Z1-9]{26,33})$')
        local lowercase = 0
        local cryptovalue = "LTC"
        check_cw_callback (task, re, lowercase, cryptovalue )
    end
})

rspamd_config:register_symbol({
    name = "RBL_SPAMHAUS_CW_XRP",
    score = 7.0,
    description = "XRP found in Spamhaus cryptowallet list",
    group = "spamhaus",
    type = "callback",
    callback = function(task)
        -- XRP regex
        local re = rspamd_re.create_cached('^(?:r[rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz]{27,35})$')
        local lowercase = 0
        local cryptovalue = "XRP"
        check_cw_callback (task, re, lowercase, cryptovalue )
    end
})

rspamd_config:register_symbol({
    name = "RBL_SPAMHAUS_MALW",
    score = 7.0,
    description = "Attachment hash is known malware",
    group = "spamhaus",
    type = "callback",
    callback = function(task)
        local ret = "127.0.3.10"
        local type = "MALW"
        check_file_callback (task, ret, type)
    end
})

rspamd_config:register_symbol({
    name = "RBL_SPAMHAUS_SUSP",
    score = 5,
    description = "Attachment hash is suspect malware",
    group = "spamhaus",
    type = "callback",
    callback = function(task)
        local ret = "127.0.3.15"
        local type = "SUSP"
        check_file_callback (task, ret, type)
    end
})
