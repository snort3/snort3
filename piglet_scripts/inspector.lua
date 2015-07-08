plugin =
{
    type = "piglet",
    version = 1,
    name = ""
}

cooked_ipv4_header = "\x45\x00\x00\x32\x00\x01\x00\x00\x40\x06\x5c\xb2\x0a\x01\x02\x03\x0a\x09\x08\x07"

piglet =
{
    name = "example test for arp spoof inspector",
    type = "inspector",
    target = "dns",
    test = function()
        print("Inspector.show:")
        Inspector.show()

        print("Inspector.eval:")
        local buf = RawBuffer.new(1024)
        buf:write(0, cooked_ipv4_header)
        local p = Packet.new(buf, 0, 100)
        local dd = DecodeData.new()
        dd:set_fields({ pkt_type = 4 })
        p:set_decode_data(dd)
        Inspector.eval(p)
        print("  result:")
        print("    packet:")
        for n, v in pairs(p:get_fields()) do print("      ", n, v) end

        print("Inspector.clear:")
        Inspector.clear(p)

        return true
    end
}
