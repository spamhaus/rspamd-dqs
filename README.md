# Use DQS with Rspamd

This repository contains configuration files for Rspamd (https://rspamd.com/) that enables you to use Spamhaus Technology Data Query Service (DQS) product

***

### Table of contents
- [What is DQS](#what-is-dqs)?
- [What are the zones available with DQS](#what-are-the-zones-available-with-dqs)?
- [What are the advantages of DQS](#what-are-the-advantages-of-dqs)?
- [How does DQS Performs](#how-does-dqs-performs)?
- [What is the licensing for DQS](#what-is-the-licensing-for-dqs)?
- [How do I register a DQS key](#how-do-i-register-a-dqs-key)?
- [Prerequisites](#prerequisites)
- [Conventions](#conventions)
- [Installation instructions](#installation-instructions)
- [Final recommendations](#final-recommendations)
- [Support and feedback](#support-and-feedback)

***

#### What is DQS

DQS (acronym for Data Query Service) is a set of DNSBLs with real time updates operated by Spamhaus Technology ([https://www.spamhaustech.com](https://www.spamhaustech.com))

***

#### What are the zones available with DQS

All zones and their meaning with all possible return codes are documented [here](https://docs.spamhaustech.com/10-data-type-documentation/datasets/030-datasets.html)

***

#### What are the advantages of DQS

There are some. First of all you will get real time updates instead of one minute delayed updates that you get querying the public mirrors or getting an RSYNC feed.
Sixty seconds doesn't seem too much but when dealing with hailstormers they are *crucial*. The increase in catch rate between public mirrors and DQS is mostly thanks to the real time updates.

Along with the above advantage you will also get two new zones to query, ZRD (Zero Reputation Domains) and AuthBL.

ZRD automatically adds newly-registered and previously dormant domains to a block list for 24 hours. It also gives you return codes that indicate the age of the domain in hours since first observation.

AuthBL is mostly dedicated to anyone that operates a submission smtp server. It's a list of IPs that are known to host bots that use stolen credentials to spam. If one of your customer gets his credentials stolen, AuthBL greatly mitigates the problem of botnets to abuse the account, and keeps your MTAs safe from being blacklisted.

***

#### How does DQS performs

You can [see it by yourself](https://www.virusbulletin.com/testing/results/latest/vbspam-email-security). We are independently tested by Virus Bulletin, that tests both DQS and public mirror performances. The difference is that DQS catches up to 42% more spam than our public mirrors.
And please be aware that that results on VBSpam are achieved by using *only* the DQS dataset, meaning that if you just add an antivirus to your email filtering setup you can possibly reach the same performance as other commercial antispam products.

***

#### What is the licensing for DQS?

The usage terms are [the same](https://www.spamhaus.org/organization/dnsblusage/) as the ones for our public mirrors, meaning that if you already use our public mirrors you are entitled for a free DQS key.

***

#### How do I register a DQS key?

It's very easy, just go [here](https://www.spamhaustech.com/dqs/) and complete the registration procedure. After you register an account, go to [this](https://portal.spamhaustech.com/manuals/dqs/) page and you'll find the DQS key under section "1.0 Datafeed Query Service".

***

#### Prerequisites

You naturally need a DQS key along with Rspamd 1.9.1+ (old rules, unsupported) or Rspamd 2.x (currently supported) already installed on your system. These instructions do not cover the initial Rspamd installation. 
To correctly install Rspamd please refer to instructions applicable to your distribution or see the documentation on the [Rspamd site](https://rspamd.com/).

***

#### Conventions

We are going to use some abbreviations and placeholders:

 * SH: Spamhaus
 * *configuration directory*: whenever you'll find these italic words, we will refer to Rspamd's configuration directory. Depending on your distribution it may be `/etc/rspamd` or other
 * whenever you find the box below, it means that you need to enter the command on your shell:
```
	$ command
```
 * whenever you find the box below, it means that you need to enter the command on a shell with root privileges:
```
	# command
```

***

#### Warning! Warning! Understand what follows!

The release of Rspamd 2.x introduced changes in the syntax and obsoleted some old configuration files. We have decided then to create a dedicated directory for each major release.

You will find a directory called 1.9 that contains the old rules for Rspamd 1.9.1+ and another, 2.x, that contains rules for the newest release. 

However, we are only going to give support for the 2.x ruleset

***

## Installation instructions

First of all, please note that we consider these configuration files as *beta*. We did some limited field tests but you are encouraged to keep an eye on the logfiles to spot any possible problem we missed. See the [support and feedback](#support-and-feedback) section below to know how to reach us.

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
- `1.9`. Directory that contains config files for Rspamd 1.9.1+
- `1.9\rbl.conf`. This file contains lookup redefinitions for the IP-based lists.
- `1.9\surbl.conf`. This file contains lookup redefinitions for the domain-based lists.
- `1.9\emails.conf`. This file contains lookup redefinitions for email addresses.
- `1.9\rbl_group.conf`. This file contains scores redefinitions.
- `2.x`. Directory that contains config files for Rspamd 2.x
- `2.x\rbl.conf`. This file contains lookup redefinitions and more for all SH lists
- `2.x\rbl_group.conf`. This file contains scores redefinitions.

Depending on the version of Rspamd you are using, enter the appropriate directory. If you have 1.9.1+:

```
	$ cd rspamd-dqs/1.9
```

Or, if you have Rspamd 2.x:


```
	$ cd rspamd-dqs/2.x
```

Now it's time to configure your DQS key. Assuming your key is `aip7yig6sahg6ehsohn5shco3z`, execute the following command:

```
	$ sed -i -e 's/your_DQS_key/aip7yig6sahg6ehsohn5shco3z/g' *.conf
```

If you are on FreeBSD then the command slightly changes:

```
	$ sed -i "" -e 's/your_DQS_key/aip7yig6sahg6ehsohn5shco3z/g' *.conf
```

There will be no output, but your key will be placed in all the needed places. Now move the configuration files in your Rspamd *configuration directory*. Assuming it is `/etc/rspamd` , execute the following command:

```
	# cp *.conf /etc/rspamd/local.d
```

Now run:

```
	# rspamadm configtest
```

If the output is:

```
	syntax OK
```

then you are done! Just restart Rspamd and you'll have the updated configuration up and running

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

We would be happy to receive some feedback from you. If you notice any problem with this installation, please open an issue in this project and we'll try to do our best to help you.

Remember that we are going to support only the latest version, so please before opening a support request be sure to be running the up to date rules from this github repository.
