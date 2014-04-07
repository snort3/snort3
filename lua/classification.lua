-- The following includes information for prioritizing rules
-- 
-- Each classification includes a shortname, a description, and a default
-- priority for that classification.
--
-- This allows alerts to be classified and prioritized.  You can specify
-- what priority each classification has.  Any rule can override the default
-- priority for that rule.
--
-- Here are a few example rules:
-- 
--   alert TCP any any -> any 80 (msg: "EXPLOIT ntpdx overflow"; 
--	dsize: > 128; classtype:attempted-admin; priority:10;
--
--   alert TCP any any -> any 25 (msg:"SMTP expn root"; flags:A+; \
--	      content:"expn root"; nocase; classtype:attempted-recon;)
--
-- The first rule will set its type to "attempted-admin" and override 
-- the default priority for that type to 10.
--
-- The second rule set its type to "attempted-recon" and set its
-- priority to the default for that type.

classifications =
{
    { name = 'not-suspicious', priority = 3,
      text = 'Not Suspicious Traffic' },

    { name = 'unknown', priority = 3,
      text = 'Unknown Traffic' },

    { name = 'bad-unknown', priority = 2,
      text = 'Potentially Bad Traffic' },

    { name = 'attempted-recon', priority = 2,
      text = 'Attempted Information Leak' },

    { name = 'successful-recon-limited', priority = 2,
      text = 'Information Leak' },

    { name = 'successful-recon-largescale', priority = 2,
      text = 'Large Scale Information Leak' },

    { name = 'attempted-dos', priority = 2,
      text = 'Attempted Denial of Service' },

    { name = 'successful-dos', priority = 2,
      text = 'Denial of Service' },

    { name = 'attempted-user', priority = 1,
      text = 'Attempted User Privilege Gain' },

    { name = 'unsuccessful-user', priority = 1,
      text = 'Unsuccessful User Privilege Gain' },

    { name = 'successful-user', priority = 1,
      text = 'Successful User Privilege Gain' },

    { name = 'attempted-admin', priority = 1,
      text = 'Attempted Administrator Privilege Gain' },

    { name = 'successful-admin', priority = 1,
      text = 'Successful Administrator Privilege Gain' },

    { name = 'rpc-portmap-decode', priority = 2,
      text = 'Decode of an RPC Query' },

    { name = 'shellcode-detect', priority = 1,
      text = 'Executable code was detected' },

    { name = 'string-detect', priority = 3,
      text = 'A suspicious string was detected' },

    { name = 'suspicious-filename-detect', priority = 2,
      text = 'A suspicious filename was detected' },

    { name = 'suspicious-login', priority = 2,
      text = 'An attempted login using a suspicious username was detected' },

    { name = 'system-call-detect', priority = 2,
      text = 'A system call was detected' },

    { name = 'tcp-connection', priority = 4,
      text = 'A TCP connection was detected' },

    { name = 'trojan-activity', priority = 1,
      text = 'A Network Trojan was detected' },

    { name = 'unusual-client-port-connection', priority = 2,
      text = 'A client was using an unusual port' },

    { name = 'network-scan', priority = 3,
      text = 'Detection of a Network Scan' },

    { name = 'denial-of-service', priority = 2,
      text = 'Detection of a Denial of Service Attack' },

    { name = 'non-standard-protocol', priority = 2,
      text = 'Detection of a non-standard protocol or event' },

    { name = 'protocol-command-decode', priority = 3,
      text = 'Generic Protocol Command Decode' },

    { name = 'web-application-activity', priority = 2,
      text = 'access to a potentially vulnerable web application' },

    { name = 'web-application-attack', priority = 1,
      text = 'Web Application Attack' },

    { name = 'misc-activity', priority = 3,
      text = 'Misc activity' },

    { name = 'misc-attack', priority = 2,
      text = 'Misc Attack' },

    { name = 'icmp-event', priority = 3,
      text = 'Generic ICMP event' },

    { name = 'inappropriate-content', priority = 1,
      text = 'Inappropriate Content was Detected' },

    { name = 'policy-violation', priority = 1,
      text = 'Potential Corporate Privacy Violation' },

    { name = 'default-login-attempt', priority = 2,
      text = 'Attempt to login by a default username and password' },

    { name = 'sdf', priority = 2,
      text = 'Senstive Data' },

    { name = 'file-format', priority = 1,
      text = 'Known malicious file or file based exploit' },

    { name = 'malware-cnc', priority = 1,
      text = 'Known malware command and control traffic' },

    { name = 'client-side-exploit', priority = 1,
      text = 'Known client side exploit attempt' }
}

