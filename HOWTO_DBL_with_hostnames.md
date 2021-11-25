**Instructions for Rspamd users**

The following config changes will enable you to use the new beta version of the Spamhaus Domain Blocklist (DBL). This beta blocklist now utilizes hostnames for compromised websites. For further information regarding the changes to the DBL, please read https://www.spamhaus.com/resource-center/hostnames-for-spamhaus-domain-blocklist/.

**IMPORTANT:** Access to the beta version of the DBL with hostnames is through the free Public Mirrors until January 31st, 2022. **However**, when it moves to production on February 1st, 2022, **it will only be available via the Data Query Service (DQS) or rsync**, i.e., not the Public Mirrors. The DQS is available for free to non-commercial users; https://www.spamhaus.com/free-trial/sign-up-for-a-free-data-query-service-account/.

**What this means for beta testers**: If you choose to change your plug-in config to test the beta DBL you will need to upgrade the plug-in to use the production version when it goes live in February. An updated plug-in will be released in early January. We will continue to make the beta zone available for two weeks after the Production version of the blocklist goes live to provide time to ensure these config changes are made.

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
