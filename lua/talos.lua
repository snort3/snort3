---------------------------------------------------------------------------
-- talos test tweaks
-- use with --talos or --tweaks talos -Q -q
---------------------------------------------------------------------------

daq =
{
    modules =
    {
        {
            name = 'pcap',
            mode = 'read-file'
        },
        {
            name = 'dump',
            variables = { 'output = none' }
        },
    },
}

normalizer = { tcp = { ips = true } }

ips.include = 'local.rules'

alerts = { alert_with_interface_name = true }

profiler =
{
    modules = { show = false },
    memory = { show = false },
    rules = { show = true }
}

