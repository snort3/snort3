run_all = function(tests)
    local failed = false

    for name, fn in pairs(tests) do
        ok, msg = pcall(fn)
        if not ok then
            print("--", name, msg)
            failed = true
        end
    end

    if failed then
        return false
    end

    return true
end

assert_table_eq = function(name, expected, actual)
    for n, exp in pairs(expected) do
        local a = actual[n]
        assert(
            exp == a,
            name .. "." .. n .. ": " .. tostring(exp) .. " != " .. tostring(a)
        )
    end
end

assert_list_eq = function(name, expected, actual)
    assert(#expected == #actual, "sizes differ")
    for i, exp in ipairs(expected) do
        local a = actual[i]
        assert(
            exp == a,
            name .. "[" .. tostring(i) .. "]" .. " != " .. tostring(a)
        )
    end
end

assert_err = function(fn, msg)
    local e, m = pcall(fn)
    assert(not e, "failed to raise an error")

    local m_s = tostring(m)
    assert(m_s:match(msg), "error message '" .. tostring(m) .. "' ! '" .. msg .. "'")
end

get_ipv4_packet = function(hdr, data)
    local rb = RawBuffer.new(hdr .. data)
    local dd = DecodeData.new()
    local p = Packet.new(rb)

    dd:set_ipv4_hdr(rb)

    p:set_data(#hdr, #data)
    p:set({ proto_bits = 4 })
    p:set_decode_data(dd)

    return p, rb
end

string.as_content_hex = function(str)
    local vals = {}
    for tok in str:gmatch("(%x+)%s*") do
        table.insert(vals, string.char(tonumber(tok, 16)))
    end

    return table.concat(vals, "")
end

string.dump_hex = function(str)
    local vals = {}
    for tok in str:gmatch(".") do
        table.insert(vals, string.format("%x", tok:byte()))
    end

    return table.concat(vals, "")
end

string.dump_human = function(str)
    local vals = {}
    for tok in str:gmatch(".") do
        if tok:match("%g") then
            table.insert(vals, tok)
        else
            table.insert(vals, ".")
        end
    end

    return table.concat(vals, "")
end

