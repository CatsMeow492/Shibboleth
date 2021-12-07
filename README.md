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

