plugin =
{
    type = "piglet",
    name = "piglet::buffer",
    test = function()
        -- Put the dofile here so that it doesn't get loaded twice
        dofile(SCRIPT_DIR .. "/common.lua")
        return run_all(tests)
    end
}

tests =
{
    initialization = function()
        local rb = RawBuffer.new()
        local buf = Buffer.new(rb)
        assert(buf)
    end
}
