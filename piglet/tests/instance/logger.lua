plugin =
{
    type = "piglet",
    name = "logger::alert_csv",
    use_defaults = true,
    test = function()
        Logger.open()
        dofile(SCRIPT_DIR .. "/common.lua")
        local rv = run_all(tests)
        Logger.close()
        return rv
    end
}

HEADER = [[
45  | 00  | 00  46 | 00 00 | 00 00 | 01 | 06
00 00 | 00 00 00 01 | 00 00 00 02

00 00 | 00 00 | 00 00 00 00 | 00 00 00 00 | 06 02
00 00 ff ff | 00 00 | 00 00 | 00 00
]]

DATA = "abcdefghijklmnopqrstuvwxyz"

get_packet = function()
    return get_ipv4_packet(HEADER:as_content_hex(), DATA)
end

tests =
{
    initialize = function()
        assert(Logger)
    end,

    reset = function()
        Logger.reset()
    end,

    alert = function()
        local p, rb = get_packet()
        local e = Event.new()
        e:set({ generator = 135, id = 2 })

        Logger.alert(p, "foo", e)
    end,
    
    log = function()
        local p, rb = get_packet()
        local e = Event.new()
        e:set({ generator = 135, id = 2 })

        Logger.log(p, "foo", e)
    end
}
