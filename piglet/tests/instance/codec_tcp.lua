plugin =
{
    type = "piglet",
    name = "codec::tcp",
    test = function()
        dofile(SCRIPT_DIR .. "/../common.lua")
        return run_tests(tests)
    end
}

PROTOCOL_IDS = { 6 }

tests =
{
    initialize = function()
        assert(Codec)
    end,

    get_protocol_ids = function()
        local rv = Codec.get_protocol_ids()
        check.arrays_equal(PROTOCOL_IDS, rv)
    end,

    decode = function()
        local daq = DAQHeader.new()
        local rb = RawBuffer.new("foobar")
        local cd = CodecData.new()
        local dd = DecodeData.new()

        local rv = Codec.decode(daq, rb, cd, dd)
        assert(not rv)
    end,

    log = function()
        local rb = RawBuffer.new()
        Codec.log(rb)
        Codec.log(rb, 0)
        print()
    end,

    encode = function()
        local rb = RawBuffer.new()
        local es = EncState.new()
        local rb_buf = RawBuffer.new(128)
        local buf = Buffer.new(rb_buf)

        local rv = Codec.encode(rb, es, buf)
        assert(rv)
    end,

    update = function()
        local rb = RawBuffer.new(64)
        assert(1)
    end,

    format = function()
        local rb = RawBuffer.new()
        local dd = DecodeData.new()

        Codec.format(true, rb, dd)
        Codec.format(false, rb, dd)
    end
}
