#!/usr/bin/env python3

# Author: m8r0wn
# License: GPL-3.0

import argparse
from os import path
from sys import argv, exit
from getpass import getpass
from datetime import datetime
from core.ldap import LdapEnum
from socket import gethostbyname

##################################################
# Fancy print statements
##################################################
def print_success(msg):
    print('\033[1;32m[+] \033[1;m{}'.format(msg))

def print_status(msg):
    print('\033[1;34m[*] \033[1;m{}'.format(msg))

def print_failure(msg):
    print('\033[1;31m[-] \033[1;m{}'.format(msg))

def print_error(msg):
    print('\033[1;33m[!] \033[1;m{}'.format(msg))

##################################################
# Resolve Domain name to get server
##################################################
def get_ip(domain):
    try:
        return gethostbyname(domain)
    except:
        return "Unable to resolve LDAP server"

##################################################
# Argparse support functions
##################################################
def parse_attrs(attrs):
    if not attrs:
        return []
    else:
        return attrs.split(",")

def file_exists(parser, filename):
    # Verify input files exists
    if not path.exists(filename):
        parser.error("Input file not found: {}".format(filename))
    return [x.strip() for x in open(filename)]

##################################################
# Display Query Data
##################################################
def display_data(resp, lookup_type, query, attrs):
    for k, v in resp.items():
        if verbose or attrs or lookup_type in ['user', 'users'] and query:
            print(k)
            for x,y in v.items():
                print("    {:<20} {}".format(x,y))
        elif query == 'eol':
            print("{}\t - {}".format(k,v['operatingSystem']))
        else:
            print(k)

##################################################
# Main
##################################################
def main(args):
    run_query = True
    start = datetime.now()
    for user in args.user:
        for passwd in args.passwd:
            try:
                if not args.srv:
                    args.srv = get_ip(args.domain)
                query = LdapEnum(user, passwd, args.hash, args.domain, args.srv, args.timeout)
                print_success("Ldap Connection - {}:{}@{} (Domain: {}) (LDAPS: {})".format(user, passwd, args.srv, args.domain,query.ldaps))

                # Only run query once, then continue to check login status
                if run_query:
                    # Users
                    if args.lookup_type in ['user', 'users']:
                        resp = query.user_query(args.query, args.attrs)

                    # Groups
                    elif args.lookup_type in ['group', 'groups']:
                        if args.query:
                            resp = query.group_membership(args.query, args.attrs)
                        else:
                            resp = query.group_query(args.attrs)

                    # Computers
                    elif args.lookup_type in ['computer', 'computers']:
                        resp = query.computer_query(args.query, args.attrs)

                    # Custom
                    elif args.lookup_type == 'custom':
                        resp = query.custom_query(args.query, args.attrs)


                    # Display results
                    if args.lookup_type and resp:
                        display_data(resp, args.lookup_type, args.query, args.attrs)
                        run_query = False

            except Exception as e:
                    if "ACCOUNT_LOCKED_OUT" in str(e):
                        print_failure("Account Locked Out - {}:{}@{}".format(user, passwd, args.srv))
                    elif debug:
                        print_error("Error - {}".format(str(e)))
    # Closing
    try:
        query.close()
        print_status("Fetched {} results in {}\n".format(len(query.data), datetime.now() - start))
    except:
        pass

if __name__ == '__main__':
    version = '0.0.6'
    try:
        args = argparse.ArgumentParser(description="""
               {0}   (v{1})
--------------------------------------------------
Perform LDAP search queries to enumerate Active Directory environments.

Usage:
    python3 {0} group -q "Domain Admins" -u user1 -p Password1 -d demo.local
    python3 {0} users -q active -u admin -p Welcome1 -d demo.local 
    """.format(argv[0], version), formatter_class=argparse.RawTextHelpFormatter, usage=argparse.SUPPRESS)
        # Main Ldap query type
        args.add_argument('lookup_type', nargs='?', help='Lookup Types: user, group, computer')
        args.add_argument('-q', dest='query', type=str, default='', help='Specify user or group to query')
        args.add_argument('-a', dest='attrs', type=str, default='', help='Specify attrs to query')

        # Domain Authentication
        user = args.add_mutually_exclusive_group(required=True)
        user.add_argument('-u', dest='user', type=str, action='append', help='Single username')
        user.add_argument('-U', dest='user', default=False, type=lambda x: file_exists(args, x), help='Users.txt file')

        passwd = args.add_mutually_exclusive_group()
        passwd.add_argument('-p', dest='passwd', action='append', default=[], help='Single password')
        passwd.add_argument('-P', dest='passwd', default=False, type=lambda x: file_exists(args, x), help='Password.txt file')
        passwd.add_argument('-H', dest='hash', type=str, default='', help='Use Hash for Authentication')

        args.add_argument('-d', dest='domain', type=str, default='', required=True, help='Domain (Ex. demo.local)')
        args.add_argument('-s', '-srv', dest='srv', type=str, default='', help='LDAP Server (optional)')

        # Alt program arguments
        args.add_argument('-t', dest='timeout', type=int, default=3, help='Connection Timeout (Default: 4)')
        args.add_argument('-v', dest="verbose", action='store_true', help="Show attribute fields and values")
        args.add_argument('-vv', dest="debug", action='store_true', help="Show connection attempts and errors")
        args = args.parse_args()

        verbose = args.verbose
        debug = args.debug
        args.attrs = parse_attrs(args.attrs)

        if args.hash:
            args.passwd.append(False)
        elif not args.passwd:
            # Get password if not provided
            args.passwd = [getpass("Enter password, or continue with null-value: ")]

        main(args)
    except KeyboardInterrupt:
        print("\n[!] Key Event Detected, Closing...")
        exit(0)