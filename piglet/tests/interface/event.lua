plugin =
{
    type = "piglet",
    name = "piglet::event",
    test = function()
        dofile(SCRIPT_DIR .. "/../common.lua")
        return run_tests(tests)
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
        check.tables_equal(VALUES, event:get())
    end,

    get_and_set = function()
        local event = Event.new()
        check.tables_equal(DEFAULT_VALUES, event:get())
        check.tables_equal(DEFAULT_SIGINFO_VALUES, event:get().sig_info)

        event:set(VALUES)
        event:set({ sig_info = SIGINFO_VALUES })

        check.tables_equal(VALUES, event:get())
        check.tables_equal(SIGINFO_VALUES, event:get().sig_info)
    end
}
