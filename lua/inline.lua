---------------------------------------------------------------------------
-- inline test tweaks
-- use with --tweaks inline
---------------------------------------------------------------------------

daq =
{
    module = 'dump',
    variables = { "load-mode=read-file", "output=none" }
}

normalizer = { tcp = { ips = true } }

