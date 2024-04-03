local rspamd_logger = require "rspamd_logger"
local rspamd_re = require "rspamd_regexp"
local rspamd_hash = require "rspamd_cryptobox_hash"
local rspamd_util = require "rspamd_util"
local rspamd_http = require "rspamd_http"

local sh_urlspec_file = rspamd_paths.DBDIR .. '/URL_normalization.yaml'
local download_url = 'https://docs.spamhaus.com/download/URL_normalization.yaml'
local hbl_spamhaus = '.hbl.dq.spamhaus.net.'
local max_url_queries = 100
local max_cw_queries = 100
local dqs_key = nil
-- If there is no problem, stat the URL file every slow_stat seconds. In case of error, try every fast_stat seconds
-- only check download file once every 2 days, because it doesn't change very often.
local slow_stat = 10.0
local fast_stat = 1.0
local download_check = 2 * 24 * 3600.0

-- table containing info for CryptoWallet symbols that are enabled
local cw_symbols = {}
local cw_all_re

-- return a combined regexp for all cryptowallets
-- Note there is a bug in rspamd_regexp, regexps that can match an empty pattern can cause hangs and memory loss.
-- See: https://github.com/rspamd/rspamd/issues/4885
-- The regexes used to match cryptowallets should never match empty strings, so should be safe to use.
-- Also note that these regexes are static, and are never freed, so we do not need a call to re:destroy().
local function combined_re(symbols)
    local sep = ""
    local cmb = ""
    for _, syminfo in pairs(symbols) do
        cmb = cmb .. sep .. syminfo.re:get_pattern()
        sep = "|"
    end
    return rspamd_re.create(cmb)
end

local cw_parent = rspamd_config:register_symbol({
    name = "spamhaus_cw",
    type = "callback",
    callback = function(task)
        if not next(cw_symbols) then
            return false
        end
        if not cw_all_re then
            cw_all_re = combined_re(cw_symbols)
        end
        if dqs_key == nil then
            rspamd_logger.warn('No DQS key set in settings.conf')
            return false
        end
        local parts = task:get_text_parts()
        if not parts then
            return false
        end
        local r = task:get_resolver()
        local maxq = max_cw_queries
        for _, part in ipairs(parts) do
            if maxq <= 0 then
                break
            end
            local words = part:filter_words(cw_all_re, "raw", maxq)
            for _, word in ipairs(words) do
                for cryptovalue, syminfo in pairs(cw_symbols) do
                    local found = syminfo.re:search(word)
                    if found then
                        local name = "RBL_SPAMHAUS_CW_" .. cryptovalue
                        local cw = found[1]
                        if syminfo.lowercase then
                            cw = cw:lower()
                        end
                        local hash = rspamd_hash.create_specific('sha256', cw):base32('rfc')
                        local lookup = hash .. '._cw.' .. dqs_key .. hbl_spamhaus
                        local function dns_cb(_, _, results, err)
                            if not results or err ~= nil then
                                return false
                            end
                            if string.find(tostring(results[1]), '127.0.') then
                                rspamd_logger.infox('found %s wallet %s (hashed: %s) in Crypto blocklist', cryptovalue, cw, hash)
                                return task:insert_result(name, 1.0, cw)
                            end
                        end
                        r:resolve_a({ task = task, name = lookup, callback = dns_cb, forced = true})
                        maxq = maxq - 1
                        break
                    end
                end
            end
        end
        return false
    end
})

local function sh_register_cw_symbol(cwinfo)
    local cw_re = rspamd_re.create(cwinfo.re)
    if not cw_re then
        rspamd_logger.warnx('Cannot compile cryptowallet regex %s', cwinfo.re)
        return
    end
    cw_symbols[cwinfo.cryptovalue] = {
        re = cw_re,
        lowercase = cwinfo.lowercase,
    }
    rspamd_config:register_symbol({
        name = "RBL_SPAMHAUS_CW_" .. cwinfo.cryptovalue,
        description = cwinfo.description,
        group = cwinfo.group,
        score = cwinfo.score,
        type = "virtual",
        parent = cw_parent,
    })
end

sh_register_cw_symbol({
    cryptovalue = "BTC",
    score = 7.0,
    description = "BTC found in Spamhaus cryptowallet list",
    group = "spamhaus",
    re = [[\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}\b]],
    lowercase = false,
})

sh_register_cw_symbol({
    cryptovalue = "ETH",
    score = 7.0,
    description = "ETH found in Spamhaus cryptowallet list",
    group = "spamhaus",
    re = [[\b0x[a-fA-F0-9]{40}\b]],
    lowercase = true,
})

sh_register_cw_symbol({
    cryptovalue = "BCH",
    score = 7.0,
    description = "BCH found in Spamhaus cryptowallet list",
    group = "spamhaus",
    re = [[\bbitcoincash:(?:q|p)[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{41,111}\b]],
    lowercase = false,
})

sh_register_cw_symbol({
    cryptovalue = "XMR",
    score = 7.0,
    description = "XMR found in Spamhaus cryptowallet list",
    group = "spamhaus",
    re = [[\b[4578][1-9A-HJ-NP-Za-km-z]{94}\b]],
    lowercase = false,
})

sh_register_cw_symbol({
    cryptovalue = "LTC",
    score = 7.0,
    description = "LTC found in Spamhaus cryptowallet list",
    group = "spamhaus",
    re = [[\b[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}\b]],
    lowercase = false,
})

sh_register_cw_symbol({
    cryptovalue = "XRP",
    score = 7.0,
    description = "XRP found in Spamhaus cryptowallet list",
    group = "spamhaus",
    re = [[\br[rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz]{27,35}\b]],
    lowercase = false,
})

-- return the end of the string for two hex ranges regex, or nil if not found
local function twohex(re)
    local hexrange = {
        "0-9",
        [[\d]],
        "a-f",
        "A-F",
    }
    local offset = 1
    for dig = 1, 2 do
        -- special case: second digit can also be "{2}"
        if dig == 2 and re:sub(offset, offset + 2) == "{2}" then
            return offset + 2
        -- must start with [ range open
        elseif re:sub(offset, offset) ~= "[" then
            return nil
        end
        offset = offset + 1
        while re:len() > offset do
            local found = false
            for _, str in ipairs(hexrange) do
                if re:sub(offset, offset + str:len() - 1) == str then
                    found = true
                    offset = offset + str:len()
                    break
                end
            end
            if not found then
                break
            end
        end
        -- we must be at the range closing ] bracket
        if re:sub(offset, offset) ~= "]" then
            return nil
        end
        offset = offset + 1
    end
    -- return the end of the string, not the next character.
    return offset - 1
end

-- reduce [range]|%[hex][hex] to just the range including the %. If that's not present, return original re
local function no_orpercent(re)
    -- there are a number of ways to write this...
    local orpercent = {
        "]|%",
        "]|(%",
        "]|(?:%",
    }
    for _, orp in ipairs(orpercent) do
        local s, e = re:find(orp, 1, true)
        if s ~= nil then
            local th = twohex(re:sub(e + 1))
            if th == nil then
                rspamd_logger.warnx("Unable to simplify regex %s because no twohex match at %s", re, re:sub(e+1))
                return re
            end
            e = e + th
            -- include closing bracket if there was an opening one
            if orp:find("(", 1, true) then
                if re:sub(e + 1, e + 1) ~= ")" then
                    rspamd_logger.warnd("Unable to simplify regex %s because no closing bracket at %s", re, re:sub(e+1))
                    return re
                else
                    e = e + 1
                end
            end
            -- pre will contain everything up to the trailing ] character.
            local pre = re:sub(1, s - 1)
            -- post is evreything after the match.
            local post = re:sub(e + 1)
            local add = "%]"
            if pre:sub(-1) == "-" then
                pre = pre:sub(1, -2)
                add = "%-]"
            end
            re = pre .. add .. post
            -- now simplify ([...]) into just [...]
            local sb, eb = re:find("%(%[%^?%]?[^]]*%]%)")
            local sclass
            if sb ~= nil then
                sclass = sb + 1
            else
                sb, eb = re:find("%(%?%:%[%^?%]?[^]]*%]%)")
                if sb ~= nil then
                    sclass = sb + 3
                end
            end
            if sb ~= nil then
                re = re:sub(1, sb - 1) .. re:sub(sclass, eb - 1) .. re:sub(eb + 1)
            end
            return re
        end
    end
    return re
end

local function re_range(re, offset)
    local _, e = re:find("^%^?%]?[^]]*%]", offset)
    if e == nil then
        rspamd_logger.warnx("Cannot parse regex range %s", re:sub(offset))
        return nil
    end
    local ret = "["
    local i = offset
    while i <= e do
        local c = re:sub(i, i)
        i = i + 1
        if c == "\\" then
            local c2 = re:sub(i, i)
            i = i + 1
            -- assume that all escaped characters translate to lua ranges. It's not exact but it's close enough.
            ret = ret .. "%" .. c2
        elseif c == "%" then
            -- explicitly escape a percent
            ret = ret .. "%%"
        else
            ret = ret .. c
        end
    end
    return ret, e
end

-- retrieve one element from a PCRE regular expression, and translate some constructs to lua patterns: ranges and escapes.
local function get_re_elem(re, offset)
    local ch = re:sub(offset, offset)
    if ch == "[" then
        return re_range(re, offset + 1)
    elseif ch == "{" then
        local _, er = re:find("^%{[%d,]+%}", offset)
        return re:sub(offset, er), er
    elseif re:len() >= offset + 2 and re:sub(offset, offset + 2) == "(?:" then
        return "(", offset + 2
    elseif ch:match("^[|()*+?.^$]") then
        -- regular match meta char
        return ch, offset
    elseif ch == "\\" then
        offset = offset + 1
        return "%" .. re:sub(offset, offset), offset
    elseif ch:match([=[^[%w%s!@#~`_=:;<>,/]]=]) then
        -- regular character or innocent meta character
        return ch, offset
    else
        -- any other character: escape it
        return "%" .. ch, offset
    end
end

-- convert PCRE-compatible regexp into lua code, loosely. Takes a few shortcuts.
local function sh_compile_re(re)
    -- options contain the possible lua match strings
    local options = {}
    -- first loose interpretation: in case a regexp contains a range followed by |%[hexchar][hexchar], simply add the % to the range
    re = no_orpercent(re)
    local reoff = 1
    -- explicitly anchor all regexes
    local thisopt = { match= "^", minsize= 0, maxsize= 0 }
    local anchor_end = false
    while reoff <= re:len() do
        local nextelem, elemend = get_re_elem(re, reoff)
        if nextelem == nil then
            return nil
        elseif nextelem == '|' then
            table.insert(options, thisopt)
            thisopt = { match = "^", minsize= 0, maxsize= 0 }
            anchor_end = false
        elseif anchor_end then
            rspamd_logger.warnx("Cannot match $ end-of-line marker halfway through regex in %s", re)
            return nil
        elseif nextelem == "^" then
            if thisopt.match ~= "^" then
                rspamd_logger.warnx("Cannot match ^ beginning-of-line marker halfway through regex in %s", re)
                return nil
            end
        elseif nextelem == "(" then
            rspamd_logger.warnx("Cannot handle grouping () in regex %s", re)
            return nil
        elseif nextelem:sub(1, 1) == "{" then
            -- handle repeat
            local minmatch, sep, repend = nextelem:match("%{(%d+)([,}])()")
            local rep = "+"
            if minmatch == nil then
                rspamd_logger.warnx("Cannot parse repeat pattern %s", nextelem)
                return nil
            elseif minmatch == 0 then
                -- minimum is zero
                rep = "*"
            end
            local maxmatch = minmatch
            if sep == "," then
                maxmatch = nextelem:sub(repend):match("(%d+)%}")
                if maxmatch == nil then
                    rspamd_logger.warnx("Cannot parse repeat pattern %s", nextelem)
                    return nil
                end
            end
            thisopt.match = thisopt.match .. rep
            thisopt.minsize = thisopt.minsize - 1 + minmatch
            thisopt.maxsize = thisopt.maxsize - 1 + maxmatch
        elseif nextelem == "*" then
            thisopt.match = thisopt.match .. nextelem
            thisopt.minsize = thisopt.minsize - 1
            thisopt.maxsize = 65536
        elseif nextelem == "+" then
            thisopt.match = thisopt.match .. nextelem
            thisopt.maxsize = 65536
        elseif nextelem == "$" then
            thisopt.match = thisopt.match .. '$'
            anchor_end = true
        else
            -- anything else matches just a single character
            thisopt.match = thisopt.match .. nextelem
            thisopt.minsize = thisopt.minsize + 1
            thisopt.maxsize = thisopt.maxsize + 1
        end
        reoff = elemend + 1
    end
    table.insert(options, thisopt)
    return function(s)
        for _, opt in ipairs(options) do
            if s:len() >= opt.minsize then
                local found = s:match(opt.match)
                if found ~= nil then
                    if found:len() > opt.maxsize and opt.maxsize < 65536 then
                        found = found:sub(1, opt.maxsize)
                    end
                    return found
                end
            end
        end
        return nil
    end
end

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
    -- XXX rspamd_regexp leaks memory, do not use it.
    -- urltable.algre[name] = rspamd_re.create(regstr)
    -- instead, compile regex loosely to lua functions that use standard lua string functions.
    local compiled_re = sh_compile_re(regstr)
    if compiled_re == nil then
        rspamd_logger.warnx('Cannot compile regex %s (for algorithm %s)', regstr, name)
        return
    end
    urltable.algref[name] = compiled_re
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
--   algre: a table mapping an algorithm to a compiled regular expression (XXX not used while regexps leak memory)
--   algref: a table mapping an algorithm to a lua function that loosely implements the regexp extraction.
--   alglower: a table mapping an algorithm to a boolean specifying if URL should be lowercased
local function load_url_spec(fname)
    rspamd_logger.infox('Loading URL normalization scheme from %s', fname)
    local urltable = { dom2alg = {}, algref = {}, alglower = {} }
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
        rspamd_logger.infox('no algorithm known for host %s', lhost)
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
    -- decode %-escaped characters
    upath = upath:gsub("%%(%x%x)", function (h)
        return string.char("0x" .. h)
    end)
    -- XXX working around memory issues in rspamd_regexp
    -- local hpart = urlspec.algre[alg]:search(upath)
    local cre = urlspec.algref[alg]
    if cre == nil then
        rspamd_logger.infox('regex not implemented for algorithm %s for url %s', alg, url:get_text())
        return
    end
    local hpart = cre(upath)
    if hpart == nil then
        rspamd_logger.warnx('URL path does not match normalization regex for algorithm %s. path=%s', alg, upath)
        return
    end
    hdata = hdata .. hpart
    if urlspec.alglower[alg] then
        hdata = hdata:lower()
    end
    local base32 = rspamd_hash.create_specific('sha256', hdata):base32('rfc')
    return base32
end

rspamd_config:register_symbol({
    name = "RBL_SPAMHAUS_HBL_URL",
    score = 7.0,
    description = "URL found in spamhaus HBL blocklist",
    group = "spamhaus",
    one_shot = true,
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
    -- XXX no regexps in use, skip
    -- for _, re in pairs(old_urlspec.algre) do
    --     re:destroy()
    -- end
    return slow_stat
end

local function download_urlspec(cfg, ev_base)
    local req_hdrs = { ['User-Agent']= 'rspamd-dqs 20240403' }
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
        if shopt.spamhaus.max_cws ~= nil then
            max_cw_queries = shopt.spamhaus.max_cws
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
