local rspamd_logger = require "rspamd_logger"
local rspamd_re = require "rspamd_regexp"
local rspamd_hash = require "rspamd_cryptobox_hash"
local rspamd_util = require "rspamd_util"

local check_cw_dns = '._cw.your_DQS_key.hbl.dq.spamhaus.net.'

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
                        rspamd_logger.infox('found ' .. cryptovalue .. ' wallet %s (hashed: %s) in Cryptowallet blocklist', word, hash)
                        return task:insert_result('RBL_SPAMHAUS_CW_' .. cryptovalue, 1.0, word);
                    end
                end
                r:resolve_a({ task = task, name = lookup , callback = dns_cb, forced = true })
            end
        end
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
