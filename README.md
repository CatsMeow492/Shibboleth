# Shibboleth 10.10.11.124

Core Concepts:

## Enumeration

As is tradition we begin with an nmap scan.

```
nmap -sV -sC -Pn 10.10.11.124 -o nmap.shibboleth.txt
```

nmap reveals a port 80 is open meaning we likely have a website.  Let's add `10.10.11.124   shibboleth.htb` to `/etc/hosts/` and browse to the site.

![Shibboleth Landing](landing-page.png)

If you've read any of my previous writeups you should know that a website screams 'GOBUSTER!'  So pick your favorite subdomain wordlist and let's go.

```
wget https://raw.githubusercontent.com/rbsec/dnscan/master/subdomains-10000.txt
gobuster dir -u shibboleth.htb -w subdomains-10000.txt
```

Gobuster revealed 2 subdomains:

```
/forms
/assets
```

![Forms Subdomain](forms.png)
![Assets Subdomain](assets.png)

Neither one of the subdomains seems to reveal anything of use.  So we continue the enumeration.  Maybe we'll have more luck with FFUF.

```
wfuzz -H "Host: FUZZ.shibboleth.htb" -w subdomains-10000.txt --hh 290 --hc 302 http://shibboleth.htb/ > fuzz.shibboleth.txt
```

Wfuzz gives us 3 more domains to work with:

```
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://shibboleth.htb/
Total requests: 9985

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                       
=====================================================================

000000110:   200        29 L     219 W      3684 Ch     "monitor"                                     
000000339:   200        29 L     219 W      3684 Ch "zabbix"                                      
000000388:   200        29 L     219 W      3684 Ch     
"monitoring"  
```

Browsing to the newfound pages we find that they all lead to the same login page. Ex. zabbix.shibboleth.htb (your /etc/hosts should look something like the copy/paste below).

```
##
# Host Database
#
# localhost is used to configure the loopback interface
# when the system is booting.  Do not change this entry.
##
127.0.0.1       localhost
255.255.255.255 broadcasthost
::1             localhost
10.10.11.124    shibboleth.htb  zabbix.shibboleth.htb   monitor.shibboleth.htb  monitoring.shibboleth.htb
```
![Zabbix Login](zabbixlogin.png)

For good measure let's gobust the zabbix.shibboleth.htb directory just in case we find something new.

```
gobuster dir -u zabbix.shibboleth.htb -w subdomains-10000.txt -o gobuster.zabbix.shiboleth.txt
gobuster dir -u zabbix.shibboleth.htb -w Filenames_or_Directories_Common.wordlist -o gobuster2.zabbix.shiboleth.txt
```

The additional scans revealed a ton of new directories including some .php directories.

A login form almost always means
.
.
.
.
.
You guessed it, an injection vector!
