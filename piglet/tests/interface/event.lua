plugin =
{
    type = "piglet",
    name = "piglet::event",
    test = function()
        -- Put the dofile here so that it doesn't get loaded twice
        dofile(SCRIPT_DIR .. "/common.lua")
        return run_all(tests)
    end
}

DEFAULT_VALUES =
{
    event_id = 0,
    event_reference = 0
}

DEFAULT_SIGINFO_VALUES =
{
    generator = 0,
    id = 0,
    rev = 0,
    class_id = 0,
    priority = 0,
    text_rule = false,
    num_services = 0
}

VALUES =
{
    event_id = 1,
    event_reference = 2
}

SIGINFO_VALUES =
{
    generator = 3,
    id = 4,
    rev = 5,
    class_id = 6,
    priority = 7,
    text_rule = true,
    num_services = 8
}

tests =
{
    init_default = function()
        local event = Event.new()
        assert(event)
    end,

    init_with_table = function()
        local event = Event.new(VALUES)
        assert_table_eq("get()", VALUES, event:get())
    end,

    get_and_set = function()
        local event = Event.new()
        assert_table_eq("get()", DEFAULT_VALUES, event:get())
        assert_table_eq("get().sig_info", DEFAULT_SIGINFO_VALUES, event:get().sig_info)

        event:set(VALUES)
        event:set({ sig_info = SIGINFO_VALUES })

        assert_table_eq("set()", VALUES, event:get())
        assert_table_eq("get().sig_info", SIGINFO_VALUES, event:get().sig_info)
    end
}
