plugin =
{
    type = "piglet",
    name = "piglet::cursor",
    test = function()
        dofile(SCRIPT_DIR .. "/../common.lua")
        return run_tests(tests)
    end
}

tests =
{
    init_default = function()
        local cur = Cursor.new()
        assert(cur)
    end,

    init_from_string = function()
        local cur = Cursor.new("abcdefgh")
        assert(cur)
    end,

    init_from_raw_buffer = function()
        local cur = Cursor.new(RawBuffer.new("abcdefgh"))
        assert(cur)
    end,

    reset_default = function()
        local cur = Cursor.new()
        cur:reset()
    end,

    reset_from_string = function()
        local cur = Cursor.new()
        cur:reset("abcdefgh")
    end,

    reset_from_raw_buffer = function()
        local cur = Cursor.new()
        cur:reset(RawBuffer.new("abcdefgh"))
    end
}
