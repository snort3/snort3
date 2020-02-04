---------------------------------------------------------------------------
-- inline test tweaks
-- use with --tweaks inline
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
            variables = { 'output=none' }
        },
    },
}

