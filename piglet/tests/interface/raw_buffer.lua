plugin =
{
    type = "piglet",
    name = "piglet::raw_buffer",
    test = function()
        dofile(SCRIPT_DIR .. "/../common.lua")
        return run_tests(tests)
    end
}

INIT_SIZE = 16
INIT_STRING = "foobar"
INIT_16_CONTENT = string.rep("00 ", 16)

tests =
{
    initialize_default = function()
        local rb = RawBuffer.new()
        assert(rb)
        assert(rb:size() == 0)
    end,

    initialize_with_size = function()
        local rb = RawBuffer.new(INIT_SIZE)
        assert(rb:size() == INIT_SIZE)
        assert(rb:read() == INIT_16_CONTENT:encode_hex())
    end,

    initialize_with_string = function()
        local rb = RawBuffer.new(INIT_STRING)
        assert(rb:size() == string.len(INIT_STRING))
        assert(rb:read() == INIT_STRING)

        rb = RawBuffer.new(INIT_STRING, INIT_SIZE)
        assert(rb:size() == INIT_SIZE)
        assert(rb:read(0, #INIT_STRING) == INIT_STRING)
        local rv = rb:read(#INIT_STRING, rb:size())
        assert(rb:read(#INIT_STRING, rb:size()) == "\0\0\0\0\0\0\0\0\0\0")
    end,

    write = function()
        local rb = RawBuffer.new()

        -- write without offset
        rb:write("foobar")
        assert(rb:size() == 6, "write() extends length")
        assert(rb:read() == "foobar")

        -- write with offset
        rb = RawBuffer.new()
        -- zero offset (should be same as no offset)
        rb:write("foobar", 0)
        assert(rb:size() == 6, "size should be 6, not " .. rb:size())
        assert(rb:read() == "foobar", "contents should be 'foobar', not '" .. rb:read() .. "'")

        -- non-zero offset
        rb = RawBuffer.new()
        rb:write("foobar", 1)
        assert(rb:size() == 7)
        assert(rb:read() == "\0foobar")
    end,

    read_empty = function()
        local rv
        local rb = RawBuffer.new()

        -- read with no args
        rv = rb:read()
        assert(#rv == 0, "length should equal 0, not " .. tostring(rv))

        -- read with 1 arg
        rv = rb:read(0)
        assert(#rv == 0, "length should equal 0, not " .. tostring(rv))

        -- read oor with 1 arg (-1, 10)
        check.raises(function() rb:read(-1) end)
        check.raises(function() rb:read(2) end)

        -- read with 2 args
        rv = rb:read(0, 0)
        assert(#rv == 0, "length should equal 0, not " .. tostring(rv))

        -- read oor with 2 args
        check.raises(function() rb:read(-1, 0) end)
        check.raises(function() rb:read(0, 2) end)
    end,

    read_nonempty = function()
        local rb = RawBuffer.new("foobar")

        -- read with no args
        local rv = rb:read()
        assert(rv == "foobar")

        -- read with 1 arg (full string)
        rv = rb:read(rb:size())
        assert(rv == "foobar")

        -- read with 1 arg (slice), length
        rv = rb:read(2)
        assert(rv == "fo")

        -- read oob with 1 arg
        check.raises(function() rb:read(10) end)

        -- read with 2 args (full string), offset, length
        rv = rb:read(0, rb:size())
        assert(rv == "foobar")

        -- read with 2 args (slice begin/end/middle)
        rv = rb:read(0, rb:size() - 1)
        assert(rv == "fooba")
        rv = rb:read(1, rb:size())
        assert(rv == "oobar")
        rv = rb:read(1, rb:size() - 1)
        assert(rv == "ooba")

        -- read oob with 2 args (offset/length)
        check.raises(function() rb:read(-1, rb:size()) end)
        check.raises(function() rb:read(0, rb:size() + 1) end)
    end,
    
    resize = function()
        local rb = RawBuffer.new()
        -- resize
        rb:resize(4)
        assert(rb:size() == 4)
        -- new contents is null-initialized
        assert(rb:read() == "\0\0\0\0")
        -- resize less
        rb:resize(3)
        assert(rb:size() == 3)
        assert(rb:read() == "\0\0\0")
    end
}
