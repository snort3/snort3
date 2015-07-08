plugin =
{
    type = "piglet",
    version = 1,
    name = ""
}

-- taken from protocols/protocol_ids.h
protocol_ids = { }
protocol_ids[0] = "hopopts"
protocol_ids[1] = "icmpv4"
protocol_ids[4] = "ip"
protocol_ids[6] = "tcp"
protocol_ids[17] = "udp"
protocol_ids[41] = "ipv6"
protocol_ids[43] = "routing"
protocol_ids[44] = "fragment"
protocol_ids[47] = "gre"
protocol_ids[50] = "esp"
protocol_ids[51] = "auth"
protocol_ids[55] = "mobility"
protocol_ids[58] = "icmpv6"
protocol_ids[59] = "nonext"
protocol_ids[60] = "dstopts"
protocol_ids[255] = "reserved"
protocol_ids[0x0800] = "ipv4"
protocol_ids[0x8035] = "revarp"
protocol_ids[0x0806] = "arp"
protocol_ids[0x8100] = "8021q"
protocol_ids[0x8137] = "ipx"
protocol_ids[0x86dd] = "ipv6"
protocol_ids[0x880b] = "ppp"
protocol_ids[0x888e] = "eapol"
protocol_ids[0x8903] = "fpath"

cooked_ipv4_header = "\x45\x00\x00\x32\x00\x01\x00\x00\x40\x06\x5c\xb2\x0a\x01\x02\x03\x0a\x09\x08\x07"

piglet =
{
    name = "example test for ipv4 codec",
    type = "codec",
    target = "ipv4",

    -- main entry point
    test = function()
        print("Codec.get_name:")
        print("  name of the codec is:", Codec.get_name())

        print("Codec.get_data_link_type:")
        local types = Codec.get_data_link_type()
        print("  data link types:")
        for n, v in pairs(types) do print("    ", n, v) end

        print("Codec.get_protocol_ids:")
        local ids = Codec.get_protocol_ids()
        print("  protocol ids:")
        for n, v in pairs(ids) do
            print("    ", n, v, protocol_ids[v])
        end

        print("Codec.decode:")
        print("  buffer:")
        -- create an underlying buffer object of length 1024
        local buf = RawBuffer.new(1024)
        print("    length:", buf:length())
        buf:write(0, cooked_ipv4_header)
        print("    contents:")
        print("    ", buf:read(0, 6))

        -- create a RawData instance with buf as it's packet data
        -- the DAQ header is pre-cooked and contains nothing but the length (1024)
        local rd = RawData.new(buf)

        -- optionally specify init proto with CodecData.new(int)
        local cd = CodecData.new()
        cd:set_fields({
            codec_flags = 0
        })

        -- you can set DecodeData fields with DecodeData.set_fields() and
        -- Decode.data.set_mplshdr_fields()
        local dd = DecodeData.new()
        dd:reset()

        local rv = Codec.decode(rd, cd, dd)
        print("  result:", rv)

        -- dump CodecData and DecodeData fields
        local cd_data = cd:get_fields()
        print("  codec data:")
        for n, v in pairs(cd_data) do print("    ", n, v) end
        local dd_data = dd:get_fields()
        print("  decode data:")
        for n, v in pairs(dd_data) do print("    ", n, v) end
        print("    mplshdr:")
        local mplshdr_data = dd:get_mplshdr_fields()
        for n, v in pairs(mplshdr_data) do print("      ", n, v) end

        print("Codec.log:")
        local lyr_len = cd:get_fields().lyr_len
        Codec.log(buf, lyr_len)
        print()

        print("Codec.encode:")
        local wbuf = RawBuffer.new(512)
        local buffer = Buffer.new(wbuf)
        local es = EncState.new(0, 0, 0, 0, 0)
        local rv = Codec.encode(buf, buf:length(), es, buffer)
        print("  result:", rv)

        print("Codec.update:")
        local updated_len = Codec.update(0, 0, buf, cd:get_fields().lyr_len)
        print("  updated_len:", updated_len)

        print("Codec.format:")
        Codec.format(true, buf, dd)
        print("  ", buf:read(0, 10))

        return true
    end
}
