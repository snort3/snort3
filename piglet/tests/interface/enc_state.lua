plugin =
{
    type = "piglet",
    name = "piglet::enc_state",
    test = function()
        -- Put the dofile here so that it doesn't get loaded twice
        dofile(SCRIPT_DIR .. "/common.lua")
        return run_all(tests)
    end
}

tests =
{
    initialize = function()
        local es = EncState.new()
        assert(es)

        es = EncState.new(0x80000000, 0xffffffff, 2, 24, 128)
        assert(es)
    end
}
