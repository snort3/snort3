plugin =
{
    type = "piglet",
    name = "ips_option::content",
    test = function()
        dofile(SCRIPT_DIR .. "/common.lua")
        return run_all(tests)
    end
}

tests =
{
    initialize = function()
        assert(IpsOption)
    end
}
