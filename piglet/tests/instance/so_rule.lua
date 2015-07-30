xplugin =
{
    type = "piglet",
    name = "so_rule::need_rule",
    test = function()
        dofile(SCRIPT_DIR .. "/common.lua")
        return run_all(tests)
    end
}

tests =
{
    initialize = function()
        assert(SoRule)
    end
}
