plugin =
{
    type = "piglet",
    name = "ips_option::content",
    test = function()
        dofile(SCRIPT_DIR .. "/../common.lua")
        return run_tests(tests)
    end
}

tests =
{
    initialize = function()
        assert(IpsOption)
    end,

    hash = function()
        local rv = IpsOption.hash()
    end,

    is_relative = function() assert(not IpsOption.is_relative()) end,

    fp_research = function() assert(not IpsOption.fp_research()) end,

    get_cursor_type = function()
        local rv = IpsOption.get_cursor_type()
        assert(rv == 1)
    end,

    eval = function()
        local rb = RawBuffer.new("foobar")
        local cur = Cursor.new(rb)
        local p = Packet.new(rb)

        local rv = IpsOption.eval(cur, p)
        assert(rv)
    end,

    action = function()
        local rb = RawBuffer.new("foobar")
        local p = Packet.new(rb)
        IpsOption.action(p)
    end
}
