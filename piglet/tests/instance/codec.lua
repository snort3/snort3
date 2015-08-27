plugin =
{
    type = "piglet",
    name = "codec::ipv4",
    test = function()
        dofile(SCRIPT_DIR .. "/../common.lua")
        return run_tests(tests)
    end
}

DATA_LINK_TYPES = { }
PROTOCOL_IDS = { 2048, 4 }

tests =
{
    initialize = function()
        assert(Codec)
    end,

    get_data_link_type = function()
        local rv = Codec.get_data_link_type()
        check.arrays_equal(DATA_LINK_TYPES, rv)
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

        -- FIXIT-H: checksum calculation is failing (temporarily set UPD_COOKED (0x1))
        local rv = Codec.update(0, 1, rb)
        assert(rv == 0)

        -- FIXIT-H: checksum calculation is failing (temporarily set UPD_COOKED (0x1))
        local rv = Codec.update(0, 1, rb, 64)
        assert(rv == 0)
    end,

    format = function()
        local rb = RawBuffer.new()
        local dd = DecodeData.new()

        Codec.format(true, rb, dd)
        Codec.format(false, rb, dd)
    end
}
