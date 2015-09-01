plugin =
{
    type = "piglet",
    name = "piglet::buffer",
    test = function()
        dofile(SCRIPT_DIR .. "/../common.lua")
        return run_tests(tests)
    end
}

tests =
{
    init_with_raw_buffer = function()
        local rb = RawBuffer.new("abcdefghijklmnopqrstuvwxyz")
        local buf = Buffer.new(rb)
        assert(buf)
    end,

    init_with_string = function()
        local buf = Buffer.new("abcdefg")
        assert(buf)
    end,

    init_with_length = function()
        local buf = Buffer.new(128)
        assert(buf)
    end,

    allocate = function()
        local buf = Buffer.new(16)
        assert(buf:allocate(10))
        assert(not buf:allocate(10))
    end,

    clear = function()
        local buf = Buffer.new(16)
        buf:allocate(16)
        buf:clear()
        assert(buf:allocate(10))
    end,

    to_string = function()
        local buf = Buffer.new("abcdefgh")
        buf:allocate(3)
        local v = tostring(buf)
        assert(#v == 3)
        assert(v == "gh\0")
    end
}
