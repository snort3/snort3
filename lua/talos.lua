---------------------------------------------------------------------------
-- talos test tweaks
-- use with --talos or --tweaks talos -Q -q
---------------------------------------------------------------------------

daq =
{
    module = 'dump',
    variables = { "load-mode=read-file", "output=none" }
}
normalizer = { tcp = { ips = true } }

ips.include = 'local.rules'

alert_fast = { packet = true }
alerts = { alert_with_interface_name = true }

profiler =
{
    modules = { show = false },
    memory = { show = false },
    rules = { show = true }
}

