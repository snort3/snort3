plugin =
{
    type = "piglet",
    name = "piglet::cursor",
    test = function()
        -- Put the dofile here so that it doesn't get loaded twice
        dofile(SCRIPT_DIR .. "/common.lua")
        return run_all(tests)
    end
}

tests =
{
    initialize = function()
        local rb = RawBuffer.new()
        local p = Packet.new(rb)
        local cur = Cursor.new(p)
        assert(cur)
    end
}
