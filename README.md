## LDAP_Search

![](https://img.shields.io/badge/Python-3.6-blue.svg)&nbsp;&nbsp;
![](https://img.shields.io/badge/License-GPL%203.0-green.svg)

LDAP_Search can be used to enumerate Users, Groups, and Computers on a Windows Domain. Authentication can be performed using traditional username and password, or NTLM hash. In addition, this tool has been modified to allow brute force/password-spraying via LDAP. Ldap_Search makes use of [Impackets](https://github.com/SecureAuthCorp/impacket/tree/python36)&nbsp;python36 branch to perform the main operations. (These are the guys that did the real heavy lifting and deserve the credit!)

## Installation
```bash
git clone --recursive https://github.com/m8r0wn/ldap_search
cd ldap_search
sudo chmod +x setup.sh
sudo ./setup.sh
```

## Usage

Enumerate all active users on a domain:
```bash
python3 ldap_search.py users -u user1 -p Password1 -d demo.local
```

Lookup a single user and display field headings:
```bash
python3 ldap_search.py users -q AdminUser -u user1 -p Password1 -d demo.local
```

Enumerate all computers on a domain:
```bash
python3 ldap_search.py computers -u user1 -p Password1 -d demo.local
```

Search for end of life systems on the domain:
```bash
python3 ldap_search.py computers -q eol -u user1 -p Password1 -d demo.local -s DC01.demo.local
```

Enumerate all groups on the domain:
```bash
python3 ldap_search.py groups -u user1 -p Password1 -d demo.local -s 192.168.1.1
```

Query group members:
```bash
python3 ldap_search.py groups -q "Domain Admins" -u user1 -p Password1 -d demo.local
```

## Queries
Below are the query options that can be specified using the "-q" argument:
```
User
  active / [None] - All active users (Default)
  all - All users, even disabled
  [specific account or email] - lookup user, ex. "m8r0wn"
  
group
  [None] - All domain groups
  [Specific group name] - lookup group members, ex. "Domain Admins"
 
computer
  [None] - All Domain Computers
  eol - look for all end of life systems on domain
```

## Options
```
positional arguments:
  lookup_type       Lookup Types: user, group, computer

optional arguments:
  -q QUERY          Specify user or group to query or use eol.
  -u USER           Single username
  -U USER           Users.txt file
  -p PASSWD         Single password
  -P PASSWD         Password.txt file
  -H HASH           Use Hash for Authentication
  -d DOMAIN         Domain (Ex. demo.local)
  -s SRV, -srv SRV  LDAP Server (optional)
  -t TIMEOUT        Connection Timeout (Default: 4)
  -v                Show Search Result Attribute Names
  -vv               Show Failed Logins & Errors
```
