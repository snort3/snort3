plugin =
{
    type = "piglet",
    name = "search_engine::ac_full",
    test = function()
        dofile(SCRIPT_DIR .. "/common.lua")
        return run_all(tests)
    end
}

tests =
{
    initialize = function()
        assert(SearchEngine)
    end
}
