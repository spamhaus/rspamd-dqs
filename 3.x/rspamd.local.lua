local rspamd_logger = require "rspamd_logger"
local rspamd_re = require "rspamd_regexp"
local rspamd_hash = require "rspamd_cryptobox_hash"
local rspamd_util = require "rspamd_util"
local rspamd_http = require "rspamd_http"

local sh_urlspec_file = rspamd_paths.DBDIR .. '/URL_normalization.yaml'
local download_url = 'https://docs.spamhaus.com/download/URL_normalization.yaml'
local hbl_spamhaus = '.hbl.dq.spamhaus.net.'
local max_url_queries = 100
local dqs_key = nil
-- If there is no problem, stat the URL file every slow_stat seconds. In case of error, try every fast_stat seconds
-- only check download file once every 2 days, because it doesn't change very often.
local slow_stat = 10.0
local fast_stat = 1.0
local download_check = 2 * 24 * 3600.0

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
                local lookup = hash .. '._cw.' .. dqs_key .. hbl_spamhaus
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

local function process_alg(urltable, alg)
    local name = alg.name
    if name == nil then
        rspamd_logger.warn('Invalid algorithm in URL normalization: no name')
        return
    end
    local _, _, regstr = alg.re:find("'([^']*)'")
    if regstr == nil then
        rspamd_logger.warnx('Invalid regex in URL normalization algorithm %s: no regex', name)
        return
    end
    urltable.algre[name] = rspamd_re.create(regstr)
    if alg.lowerhash and alg.lowerhash == "true" then
        urltable.alglower[name] = true
    end
    if not alg.domains or #alg.domains == 0 then
        urltable.default = name
    else
        for _, d in ipairs(alg.domains) do
            urltable.dom2alg[d] = name
        end
    end
end

-- returns a table with URL specs. The table contains a few entries:
--   dom2alg: a table mapping a domain to an algorithm
--   default: the name of the default algorithm
--   algre: a table mapping an algorithm to a compiled regular expression
--   alglower: a table mapping an algorithm to a boolean specifying if URL should be lowercased
local function load_url_spec(fname)
    rspamd_logger.infox('Loading URL normalization scheme from %s', fname)
    local urltable = { dom2alg = {}, algre = {}, alglower = {} }
    local alg = {}
    local in_domains = false
    local fh, err = io.open(fname)
    if fh == nil then
        rspamd_logger.warnx('Cannot open %s: %s', fname, err)
        return
    end
    -- don't try to parse the YAML as such, since we know the yaml structure, just assume how it looks
    for yline in fh:lines() do
        if yline:sub(1, 1) == "-" then
            if next(alg) then
                process_alg(urltable, alg)
            end
            alg = {}
            in_domains = false
        end
        if in_domains and yline:sub(1, 5) == "    -" then
            local _, _, dom = yline:find("(%g+)", 6)
            if dom ~= nil then
                table.insert(alg.domains, dom)
            end
        else
            local _, eospace, key = yline:find("(%w+):%s*", 2)
            if key == "domains" then
                alg.domains = {}
                in_domains = true
            elseif key ~= nil then
                in_domains = false
                alg[key] = yline:sub(eospace + 1)
            else
                rspamd_logger.warnx('Cannot parse line in URL normalization: %s', yline)
            end
        end
    end
    if not fh:close() then
        rspamd_logger.warnx('Error reading file %s', fname)
        return
    end
    if next(alg) then
        process_alg(urltable, alg)
    end
    return urltable
end

local sh_urlspec = nil
local sh_url_mtime = nil

local function url_to_hash(url, urlspec)
    local lhost = url:get_host():lower()
    local alg = urlspec.dom2alg[lhost] or urlspec.default
    if alg == nil then
        return
    end
    local hdata = lhost
    if url:get_port() ~= nil then
        hdata = hdata .. ":" .. url:get_port()
    end
    local upath = url:get_path()
    if upath ~= nil then
        upath = "/" .. upath
    else
        upath = ""
    end
    local uquery = url:get_query()
    if uquery ~= nil then
        upath = upath .. "?" .. uquery
    end
    local ufragment = url:get_fragment()
    if ufragment ~= nil then
        upath = upath .. "#" .. ufragment
    end
    local hpart = urlspec.algre[alg]:search(upath)
    if hpart == nil then
        rspamd_logger.infox('URL path does not match normalization regex for algorithm %s. path=%s', alg, upath)
        return
    end
    hdata = hdata .. hpart[1]
    if urlspec.alglower[alg] then
        hdata = hdata:lower()
    end
    local base32 = rspamd_hash.create_specific('sha256', hdata):base32('rfc')
    return base32
end

rspamd_config:register_symbol({
    name = "RBL_SPAMHAUS_HBL_URL",
    score = 7.0,
    description = "URL found in spamhaus HBL blacklist",
    group = "spamhaus",
    type = "callback",
    callback = function(task)
        if dqs_key == nil then
            rspamd_logger.warn('No DQS key set in settings.conf')
            return false
        end
        if sh_urlspec == nil then
            rspamd_logger.warn('URL normalization scheme not loaded yet, cannot check URLs')
            return false
        end
        local urls = task:get_urls(false, true)
        if urls == nil then
            return false
        end
        local r = task:get_resolver()
        local count = max_url_queries
        for _, url in ipairs(urls) do
            count = count - 1
            if count <= 0 then
                return false
            end
            local hash = url_to_hash(url, sh_urlspec)
            if hash ~= nil then
                local lookup = hash .. '._url.' .. dqs_key .. hbl_spamhaus
                local function dns_cb(_, _, results, err)
                    if not results or err ~= nil then
                        return false
                    end
                    if (string.find(tostring(results[1]), '127.0.')) then
                        rspamd_logger.infox('found URL %s (hash: %s) in HBL.URL blocklist', url:get_text(), hash)
                        return task:insert_result('RBL_SPAMHAUS_HBL_URL', 1.0, url:get_text());
                    end
                end
                r:resolve_a({ task = task, name = lookup , callback = dns_cb, forced = true })
            end
        end
    end
})

-- If the urlspec file changed on disk, load it and update the urlspec
local function reload_urlspec(_, _)
    local err, stat = rspamd_util.stat(sh_urlspec_file)
    if err ~= nil then
        -- error reading file, try again in 1 second
        return fast_stat
    end
    if sh_urlspec ~= nil and sh_url_mtime == stat.mtime then
        return slow_stat
    end
    local new_urlspec = load_url_spec(sh_urlspec_file)
    if new_urlspec == nil then
        return fast_stat
    end
    sh_url_mtime = stat.mtime
    local old_urlspec = sh_urlspec
    sh_urlspec = new_urlspec
    if old_urlspec == nil then
        return slow_stat
    end
    -- Cleanup the regexes from the old urlspec
    for _, re in ipairs(old_urlspec.algre) do
        re:destroy()
    end
    return slow_stat
end

local function download_urlspec(cfg, ev_base)
    local req_hdrs = { ['User-Agent']= 'rspamd-dqs 20240208' }
    local _, stat = rspamd_util.stat(sh_urlspec_file)
    if stat ~= nil then
        req_hdrs['If-Modified-Since'] = rspamd_util.time_to_string(stat.mtime)
    end
    local function download_cb(err_msg, code, body, resp_hdrs)
        if code == 304 then
            -- not modified
            return
        elseif code ~= 200 then
            rspamd_logger.warnx('Cannot download %s. Result: %s %s', download_url, code, err_msg)
            return
        end
        if body == nil then
            rspamd_logger.warnx('No result body downloading %s', download_url)
            return
        end
        local sh_urlspec_temp = sh_urlspec_file .. ".tmp"
        local fh, err = io.open(sh_urlspec_temp, "w")
        if fh == nil then
            rspamd_logger.warnx('Cannot write to %s: %s', sh_urlspec_temp, err)
            return
        end
        local ok, werr = fh:write(body)
        if ok == nil then
            rspamd_logger.warnx('Error writing to %s: %s', sh_urlspec_temp, werr)
            return
        end
        if not fh:close() then
            rspamd_logger.warnx('Error closing %s', sh_urlspec_temp)
            return
        end
        local lm = resp_hdrs['last-modified']
        if lm ~= nil then
            local lmunix = rspamd_util.parse_smtp_date(lm)
            if lmunix ~= nil then
                local touchdate = os.date("%Y%m%d%H%M.%S", lmunix)
                -- try to give the file the same timestamp as we got from the last-modified header.
                -- if this fails, too bad.
                os.execute(string.format('touch -t %s "%s"', touchdate, sh_urlspec_temp))
            end
        end
        os.rename(sh_urlspec_temp, sh_urlspec_file)
        rspamd_logger.infox('Downloaded new %s', sh_urlspec_file)
    end

    rspamd_http.request({
        ev_base = ev_base,
        config = cfg,
        url = download_url,
        headers = req_hdrs,
        callback = download_cb,
    })
    return true
end

rspamd_config:add_on_load(function(cfg, ev_base, worker)
    local shopt = rspamd_config:get_all_opt('settings')
    if shopt ~= nil and shopt.spamhaus ~= nil then
        dqs_key = shopt.spamhaus.dqs
        if shopt.spamhaus.max_urls ~= nil then
            max_url_queries = shopt.spamhaus.max_urls
        end
        if shopt.spamhaus.download_check ~= nil then
            download_check = shopt.spamhaus.download_check
        end
        if shopt.spamhaus.download_url ~= nil then
            download_url = shopt.spamhaus.download_url
        end
    end
    if dqs_key == nil then
        rspamd_logger.warnx('WARNING: no DQS key set, cannot verify cryptowallets and URLs.')
        -- may as well return now, no point setting up refreshing.
        return
    end
    local refresh = reload_urlspec(cfg, ev_base)
    rspamd_config:add_periodic(ev_base, refresh, reload_urlspec)
    if worker:is_primary_controller() then
        if refresh == fast_stat then
            download_urlspec(cfg, ev_base)
        end
        if download_check == 0 then
            -- turn off periodic download checks
            return
        elseif download_check < 3600 then
            -- minimum download check. This file does not change very often. Default is 2 days.
            download_check = 3600
        end
        rspamd_config:add_periodic(ev_base, download_check, download_urlspec, true)
    end
end)
