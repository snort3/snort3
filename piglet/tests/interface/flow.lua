plugin =
{
    type = "piglet",
    name = "piglet::flow",
    test = function()
        dofile(SCRIPT_DIR .. "/../common.lua")
        return run_tests(tests)
    end
}

tests =
{
    initialize = function()
        local flow = Flow.new()
        assert(flow)

        flow = Flow.new(1)
        assert(flow)
    end,

    reset = function()
        local flow = Flow.new()
        flow:reset()
    end
}
