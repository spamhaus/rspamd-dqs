# Use DQS with Rspamd

This repository contains configuration files for Rspamd (https://rspamd.com/) that enables you to use Spamhaus Technology Data Query Service (DQS) product

- What is DQS?

DQS is a set of DNSBLs with real time updates.

- How does DQS performs?

You can [see it by yourself](https://www.virusbulletin.com/testing/results/latest/vbspam-email-security). We are independently tested by Virus Bulletin, that tests both DQS and public mirror performances. The difference is that DQS catches up to 42% more spam than our public mirrors.
And please be aware that that results on VBSpam are achieved by using *only* the DQS dataset, meaning that if you just add an antivirus to your email filtering setup you can possibly reach the same performance as other commercial antispam products.

- What is the licensing for DQS?

The usage terms are [the same](https://www.spamhaus.org/organization/dnsblusage/) as the ones for our public mirrors, meaning that if you already use our public mirrors you are entitled for a free DQS key.

- How do I register a DQS key?

It's very easy, just go [here](https://www.spamhaustech.com/dqs/) and complete the registration procedure. After you register an account, go to [this](https://portal.spamhaustech.com/src/manual/dqs/) page and note the DQS key.


##Installation instructions


## Prerequisites

You naturally need a DQS key along with Rspamd 1.9+ already installed on your system. These instructions do not cover the initial Rspamd installation. 
To correctly install Rspamd please refer to instructions applicable to your distribution or see the documentation on the [Rspamd site](https://rspamd.com/).

## Conventions

We are going to use some abbreviations and placeholders:

 * SH: Spamhaus
 * *configuration directory*: whenever you'll find these italic words, we will refer to the Rspamd configuration directory. It usually is `/etc/rspamd`, unless you installed it by using sources rather than a package.
 * whenever you find the box below, it means that you need to enter the command on your shell:
```
	$ command
```
 * whenever you find the box below, it means that you need to enter the command on a shell with root privileges:
```
	# command
```

## Installation instructions

First of all, please note that we consider these configuration files as *beta*. We did some limited field tests but you are encouraged to keep an eye on the logfiles to spot any possible problem we missed. See the **Support** section below to know how to reach us.

Start with downloading all the needed files:

```
	$ git clone https://github.com/spamhaus/rspamd-dqs
	Cloning into 'rspamd-dqs'...
	remote: Enumerating objects: 10, done.
	remote: Counting objects: 100% (10/10), done.
	remote: Compressing objects: 100% (8/8), done.
	remote: Total 10 (delta 0), reused 10 (delta 0), pack-reused 0
	Unpacking objects: 100% (10/10), done.
```

A subdirectory called `rspamd-dqs` will be created. Within it you will find the following files:

 - `README.md`. This is just a pointer to this document.
 - `rbl.conf`. This file contains lookup redefinitions for the IP-based lists.
 - `surbl.conf`. This file contains lookup redefinitions for the domain-based lists.
- `emails.conf`. This file contains lookup redefinitions for email addresses.
- `rbl_group.conf`. This file contains scores redefinitions.


Now it's time to configure your DQS key. Assuming your key is `aip7yig6sahg6ehsohn5shco3z`, execute the following command:

```
	$ cd rspamd-dqs
	$ sed -i -e 's/your_DQS_key/aip7yig6sahg6ehsohn5shco3z/g' *.conf
```

There will be no output, but your key will be placed in all the needed places. Now move the configuration files in your Rspamd *configuration directory*. Assuming it is `/etc/rspamd` , execute the following command:

```
	# cp *.conf /etc/rspamd/local.d
```

You are done! Just restart rspamd and you'll have the updated configuration up and running

## Final recommendations

We already said that the configuration in the VBSpam survey make use exclusively of our data, as our goal was certifying their quality and keep an eye on how we perform in the field.

While the results are reasonably good, the malware/phishing scoring can certainly be improved through some additional actions that we recommend.

- Install an antivirus software on your mailserver
- Nowadays the rule of thumb for receiving email should be to stay defensive, that is why we recommend to do basic attachment filtering by dropping all emails that contains potentially hazardous attachments, like *at least* all file extensions that match this regex:

```
(exe|vbs|pif|scr|bat|cmd|com|cpl|dll|cpgz|chm|js|jar|wsf)
```

- You should also drop, by default, all Office documents with macros.

## Support and feedback

We would be happy to receive some feedback from you. If you notice any problem with this installation, please drop us a note at datafeed-support@spamteq.com and we'll try to do our best to help you.