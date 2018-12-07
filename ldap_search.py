#!/usr/bin/env python3

# Author: m8r0wn
# License: GPL-3.0
# Description: Perform Ldap queries and enumerate Active Directory environments.

from core.ldap import LdapEnum

def print_success(msg):
    print('\033[1;32m[+] \033[1;m{}'.format(msg))

def print_status(msg):
    print('\033[1;34m[*] \033[1;m{}'.format(msg))

def print_failure(msg):
    print('\033[1;31m[-] \033[1;m{}'.format(msg))

def print_error(msg):
    print('\033[1;33m[!] \033[1;m{}'.format(msg))

def file_exists(parser, filename):
    # Used with argparse to check if input files exists
    if not path.exists(filename):
        parser.error("Input file not found: {}".format(filename))
    return [x.strip() for x in open(filename)]

def get_ip(domain):
    from socket import gethostbyname
    try:
        return gethostbyname(domain)
    except:
        return "Unable to resolve LDAP server"

def display_eol(resp):
    # Filter results and show all End of Life OS
    for k,v in resp.items():
            if str(v['operatingSystemVersion']).startswith(('3','4','5','6.0')):
                print_success("{:<20}\t(OS: {})".format(v['dNSHostName'], v['operatingSystem']))

def display_all(resp, args):
    for result in resp:
        for k, v in resp[result].items():
            # Print all, including attributes
            if args.verbose or args.lookup_type in ['user', 'users'] and args.query:
                try:
                    s = v.split(",")
                    print("{} - {}:".format(result, k))
                    for x in s:
                        print("\t{}".format(x))
                except:
                    print("{} - {}:\t{}".format(result, k, v))
            else:
                # Just print result values
                print(v)

def main(args):
    run_query = True
    for user in args.user:
        for passwd in args.passwd:
            try:
                # Set server if not set
                if not args.srv:
                    args.srv = get_ip(args.domain)

                # Init Class / Con
                query = LdapEnum(user, passwd, args.hash, args.domain, args.srv, args.timeout)

                start = datetime.now()
                print_success("Ldap Connection - {}:{}@{} (Domain: {}) (LDAPS: {})".format(user, passwd, args.srv, args.domain,query.ldaps))

                # Only run query once, then continue to check login status
                if not run_query: break

                # Send Query
                if args.lookup_type in ['user', 'users']:
                    resp = query.user_query(args.query)
                elif args.lookup_type in ['group', 'groups']:
                    if args.query:
                        resp = query.group_membership(args.query)
                    else:
                        resp = query.group_query()
                elif args.lookup_type in ['computer', 'computers']:
                    resp = query.computer_query()


                # Display results
                if args.lookup_type and resp:
                    if args.query == "eol":
                        display_eol(resp)
                    else:
                        display_all(resp, args)
                    # If successful, dont search again - used for brute forcing
                    run_query = False

            except Exception as e:
                if args.debug:
                    if "ACCOUNT_LOCKED_OUT" in str(e):
                        print_failure("Account Locked Out - {}:{}@{}".format(user, passwd, args.srv))

                    elif "LOGON_FAILURE" in str(e):
                        print_failure("Login Failed - {}:{}@{}".format(user, passwd, args.srv))


                    elif "invalidCredentials:" in str(e):
                        print_failure("Login Failed - {}:{}@{}".format(user, passwd, args.srv))

                    elif "Connection error" in str(e):
                        print_error("Connection Error - {} (Domain: \"{}\")".format(args.srv, args.domain))
                    else:
                        print_error("Error - {}".format(str(e)))

            # Display results and close
            try:
                count = len(query.data)
                query.close()
                stop = datetime.now()
                print_status("Fetched {} results in {}\n".format(count, stop - start))
            except Exception as e:
                pass

if __name__ == '__main__':
    import argparse
    from os import path
    from sys import argv, exit
    from getpass import getpass
    from datetime import datetime

    version = '0.0.4'
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
        args.add_argument('-v', dest="verbose", action='store_true', help="Show search result Field names")
        args.add_argument('-vv', dest="debug", action='store_true', help="Show Failed logons & Errors")
        args = args.parse_args()

        if args.hash:
            args.passwd.append(False)
        elif not args.passwd:
            # Get password if not provided
            args.passwd = getpass("Enter password, or continue with null-value: ")

        main(args)
    except KeyboardInterrupt:
        print("\n[!] Key Event Detected, Closing...")
        exit(0)