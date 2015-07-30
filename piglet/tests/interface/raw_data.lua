plugin =
{
    type = "piglet",
    name = "piglet::raw_data",
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
        local daq = DAQHeader.new()
        local rd = RawData.new(rb, daq)
        assert(rd)
    end
}
