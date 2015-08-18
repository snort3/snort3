do
    local table = table
    local meta = { __index = table}

    -- give tables metatable access to the table library
    function table.new(t)
        t = t or { }
        setmetatable(t, meta)
        return t
    end

    function table:imap(fn)
        local iter, a, s = ipairs(self)
        local closure = function(...)
            local i, v = iter(...)
            return i, fn(v)
        end

        return closure, self, 0
    end

    function table:ifilter(fn)
        local iter, a, s = ipairs(self)
        local closure = function(...)
            local i, v = iter(...)
            while i ~= nil and not fn(v) do
                i, v = iter(a, i)
            end

            return i, v
        end

        return closure, self, 0
    end

    function table:vomit(depth, seen, out)
        depth = depth or 0

        -- maintain a list of dumped tables to
        -- avoid infinite loops
        seen = seen or { }
        out = out or { }

        local indent = strint.rep("  ", level)

        for n, v in pairs(self) do
            if type(v) == "table" and not seen[v] then
                seen[v] = true
                table.insert(out, string.format("%s%s =", indent, tostring(n)))
                self.vomit(v, depth + 1, seen, out)
            else
                table.insert(out, string.format("%s%s = %s", indent, tostring(n), tostring(v)))
            end
        end

        return table.concat(out, "\n")
    end

    function meta:__tostring()
        if DEBUG then
            return self:vomit()
        else
            return table.__tostring(self)
        end
    end
end

-- string library extensions
do
    function string:encode_hex()
        local out = table.new()

        for tok in self:gmatch("%f[%x](%x%x)") do
            if tok:gmatch("^%x+$") then
                out:insert(string.char(tonumber(tok, 16)))
            end
        end

        return out:concat("")
    end

    function string:decode_printable()
        local out = table.new()

        for tok in self:gmatch(".") do
            if tok:match("%g") then
                out:insert(tok)
            else
                out:insert(".")
            end
        end

        return out:concat("")
    end

    function string:decode_hex()
        local out = table.new()

        for tok in self:gmatch(".") do
            out:insert(string.format("%02x", string.byte(tok)))
        end

        return out:concat(" ")
    end
end

-- Assertions library
check = { }
do
    function raise(title, msg, lvl)
        lvl = lvl or 3
        local info = debug.getinfo(lvl)
        error(
            string.format(
                "%s:%d: %s: %s",
                info.short_src,
                info.currentline,
                title,
                msg
            )
        )
    end

    function check.tables_equal(exp, act)
        if exp == act then return end

        for n, e in pairs(exp) do
            local a = act[n]
            if a ~= e then
                raise(
                    "tables unequal",
                    string.format(
                        "item with key %s differs (%s ~= %s)",
                        tostring(n),
                        tostring(e),
                        tostring(a)
                    )
                )
            end
        end
    end

    function check.arrays_equal(exp, act)
        if exp == act then return end
        if #exp ~= #act then
            raise(
                "arrays unequal",
                string.format(
                    "lengths differ (#%d ~= #%d)",
                    #exp, #act
                )
            )
        end

        for i, e in ipairs(exp) do
            local a = act[i]
            if e ~= a then
                raise(
                    "arrays unequal",
                    string.format(
                        "item at index %d differs (%s ~= %s)",
                        i, tostring(e), tostring(a)
                    )
                )
            end
        end
    end

    function check.raises(fn, msg)
        local ok, err = pcall(fn)
        if ok then
            raise("did not throw", msg or "")
        end
    end

    function check.check(expr, msg)
        if not expr then
            raise("assertion failed", msg or "")
        end
    end
end

-- Test runner
function run_tests(tests)
    local failed = false

    for name, fn in pairs(tests) do
        ok, err = pcall(fn)
        if not ok then
            print("--", name, err)
            failed = true
        end
    end

    return not failed
end

-- Misc utils
packet = { }
do
    function packet.construct_ip4(hdr, data)
        local rb = RawBuffer.new(hdr .. data)
        local dd = DecodeData.new()
        local p = Packet.new(rb)

        local ip_api = dd:get_ip_api()
        ip_api:set_ip4(rb)

        p:set_data(#hdr, #data)
        p:set { proto_bits = 4 }
        p:set_decode_data(dd)

        return p
    end
end
