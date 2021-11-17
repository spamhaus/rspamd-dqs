**Instructions for Rspamd users**

These instructions will help you participate in the beta testing of the new Spamhaus DBL with hostnames. More informations about the changes that are being introduced can be found here: https://www.spamhaus.com/resource-center/hostnames-for-spamhaus-domain-blocklist/

To use the beta version of the Spamhaus Domain Blockilst (DBL) with hostnames, all you need to do is install the DQS plugin, following the instructions found here: https://github.com/spamhaus/rspamd-dqs, and make a few simple changes to the code, as detailed below:

Edit the `rbl.conf` file. It's usually located in `/etc/rspamd/local.d/rbl.conf`. 

Add the following section just after the line that starts with `rbls {`

    spamhaus_dbl_fullurls {
        ignore_defaults = true;
        no_ip = true;
        rbl = "dbl-beta.spamhaus.org";
        selector = 'urls:get_host'
        disable_monitoring = true;
        returncodes {
            DBLABUSED_SPAM_FULLURLS = "127.0.1.102";
            DBLABUSED_PHISH_FULLURLS = "127.0.1.104";
            DBLABUSED_MALWARE_FULLURLS = "127.0.1.105";
            DBLABUSED_BOTNET_FULLURLS = "127.0.1.106";
        }
    }

Edit the `rbl_group.conf` file. It's usually located in `/etc/rspamd/local.d/rbl_group.conf`. 

Add the following section just after the line that starts with `symbols = {`

    "DBLABUSED_SPAM_FULLURLS" {
        weight = 5.5;
        description = "DBL uribl abused legit spam";
        groups = ["spamhaus"];
    }
    "DBLABUSED_PHISH_FULLURLS" {
        weight = 5.5;
        description = "DBL uribl abused legit phish";
        groups = ["spamhaus"];
    }
    "DBLABUSED_MALWARE_FULLURLS" {
        weight = 5.5;
        description = "DBL uribl abused legit malware";
        groups = ["spamhaus"];
    }
    "DBLABUSED_BOTNET_FULLURLS" {
        weight = 5.5;
        description = "DBL uribl abused legit botnet";
        groups = ["spamhaus"];
    }

That's it! Just run `rspamadm configtest` and ensure that the last line of output is `syntax OK`.
