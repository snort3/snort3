plugin =
{
    type = "piglet",
    name = "logger::alert_fast",
    use_defaults = true,
    test = function()
        dofile(SCRIPT_DIR .. "/../common.lua")

        Logger.open()
        local rv = run_tests(tests)
        Logger.close()
        return rv
    end
}

IP4 = [[
45  | 00  | 00  46 | 00 00 | 00 00 | 01 | 06
00 00 | 00 00 00 01 | 00 00 00 02

00 00 | 00 00 | 00 00 00 00 | 00 00 00 00 | 06 02
00 00 ff ff | 00 00 | 00 00 | 00 00
]]

DATA = "abcdefghijklmnopqrstuvwxyz"

tests =
{
    exists = function()
        assert(Logger)
    end,

    reset = function()
        Logger.reset()
    end,

    alert = function()
        local p = packet.construct_ip4(IP4:encode_hex(), DATA)
        local e = Event.new()

        e:set { generator = 135, id = 2 }

        Logger.alert(p, "foo", e)
    end,
    
    log = function()
        local p = packet.construct_ip4(IP4:encode_hex(), DATA)
        local e = Event.new()

        e:set { generator = 135, id = 2 }

        Logger.log(p, "foo", e)
    end
}
