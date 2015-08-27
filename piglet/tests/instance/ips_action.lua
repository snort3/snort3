plugin =
{
    type = "piglet",
    name = "ips_action::react",
    test = function()
        dofile(SCRIPT_DIR .. "/../common.lua")
        return run_tests(tests)
    end
}

tests =
{
    initialize = function()
        assert(IpsAction)
    end,

    exec = function()
        local rb = RawBuffer.new()
        local p = Packet.new(rb)
        IpsAction.exec(p)
    end
}
