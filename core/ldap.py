#!/usr/bin/env python3

# Author: m8r0wn
# License: GPL-3.0
# Description: Class to perform LDAP search queries
# Credit / Resources: https://github.com/SecureAuthCorp/impacket

from impacket.ldap import ldap

class LdapEnum():
    def __init__(self, user, passwd, hash, domain, host, timeout):
        self.ldaps = False
        self.domain = domain
        self.baseDN = ''

        # Set domain name for baseDN
        try:
            for x in self.domain.split('.'):
                self.baseDN += 'dc={},'.format(x)

            # Remove last ','
            self.baseDN = self.baseDN[:-1]
        except:
            self.baseDN = 'dc={}'.format(self.domain)

        # If srv not provided, use domain name
        if not host:
            self.host = self.domain
        else:
            self.host = host

        # Create Ldap(s) Connection
        try:
            self.ldap_connect(self.host)
        except:
            self.ldaps_connect(self.host)
        self.con._socket.settimeout(timeout)

        # Authentication
        self.ldap_auth(user, passwd, hash, self.domain)

    ##################################################
    # Ldap Connection & Authentication
    ##################################################
    def ldap_connect(self, srv):
        self.con = ldap.LDAPConnection("ldap://{}".format(srv), )

    def ldaps_connect(self, srv):
        self.con = ldap.LDAPConnection("ldaps://{}".format(srv), )
        self.ldaps = True

    def ldap_auth(self, user, passwd, hash, domain):
        lm = ''
        nt = ''
        if hash:
            try:
                lm, nt = hash.split(':')
            except:
                nt = hash
            self.con.login(user, '', domain, lmhash=lm, nthash=nt)
        else:
            self.con.login(user, passwd, domain, '', '')

    ##################################################
    # Ldap Query Function
    ##################################################
    def ldap_query(self, searchFilter, attrs, parser):
        sc = ldap.SimplePagedResultsControl(size=9999)
        try:
            resp = self.con.search(searchBase=self.baseDN, searchFilter=searchFilter, attributes=attrs,
                                   searchControls=[sc], sizeLimit=0, timeLimit=50, perRecordCallback=parser)
        except ldap.LDAPSearchError as e:
            raise Exception("ldap_query error: {}".format(str(e)))

    ##################################################
    # Ldap Search Types
    ##################################################
    def user_query(self, query, attrs):
        self.data = {}
        if not attrs:
            attrs = ['Name', 'userPrincipalName', 'sAMAccountName', 'mail', 'company', 'department', 'mobile',
                     'telephoneNumber', 'badPwdCount', 'userWorkstations', 'manager', 'memberOf', 'manager']

        #DEFAULT: Show only active users
        search = "(&(objectCategory=person)(objectClass=user)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"

        # Show all users even disabled
        if query == 'all':
            search = "(&(objectCategory=person)(objectClass=user))"
        # Lookup user by email
        elif '@' in query:
            search = '(&(objectClass=user)(mail:={}))'.format(query.lower())

        # Lookup user by username
        elif query and query not in ['active', 'Active']:
            search = "(&(objectClass=user)(sAMAccountName:={}))".format(query.lower())

        # Execute query
        self.ldap_query(search, attrs, self.generic_parser)
        return self.data

    def computer_query(self, query, attrs):
        if not attrs:
            attrs = ['dNSHostName', 'operatingSystem', 'operatingSystemVersion', 'operatingSystemServicePack']

        self.data = {}
        search = '(&(objectClass=Computer))'
        self.ldap_query(search, attrs, self.generic_parser)

        # Filter results for end of life operating systems
        if query == "eol":
            self.data = self.eol_filter(self.data)
        return self.data

    def group_query(self, attrs):
        if not attrs:
            attrs = ['distinguishedName', 'cn']

        self.data = {}
        search = '(&(objectCategory=group))'
        self.ldap_query(search, attrs, self.generic_parser)
        return self.data

    def group_membership(self, group, attrs):
        if not attrs:
            attrs = ['member']

        self.data = {}
        search = '(&(objectCategory=group)(cn={}))'.format(group)
        self.ldap_query(search, attrs, self.group_membership_parser)
        return self.data

    def custom_query(self, query, attrs):
        if not query or not attrs:
            raise Exception("Query / Attrs not provided for custom LDAP search")
        self.data = {}
        self.ldap_query(query, attrs, self.generic_parser)
        return self.data

    ##################################################
    # LDAP Data Parsers
    ##################################################
    def generic_parser(self, resp):
        tmp = {}
        dtype = ''
        resp_data = ''
        try:
            for attr in resp['attributes']:
                dtype = str(attr['type'])

                # catch formatting issues
                if "SetOf:" in str(attr['vals']):
                    resp_data = str(attr['vals'][0])
                else:
                    resp_data = str(attr['vals'])

                tmp[dtype] = resp_data
            # Add to class obj & cleanup
            self.categorize(tmp)
            del (tmp)
        except Exception as e:
            if "list indices must be integers or slices, not str" not in str(e):
                raise Exception(e)

    def group_membership_parser(self, resp):
        try:
            for attr in resp['attributes']:
                for member in attr['vals']:
                    attrs = ['sAMAccountName']
                    cn = str(member).split(',')[0]
                    search = "(&({}))".format(cn)
                    self.ldap_query(search, attrs, self.generic_parser)
        except:
            pass

    def eol_filter(self, resp):
        # Parse results looking for end of life systems
        data = {}
        for k, v in resp.items():
            try:
                if str(v['operatingSystemVersion']).startswith(('3', '4', '5', '6.0')):
                    data[k] = v
            except:
                pass
        return data

    def categorize(self, tmp):
        # Take temp data, sort and move to class object
        for x in ['sAMAccountName', 'dNSHostName', 'cn']:
            try:
                self.data[tmp[x].lower()] = tmp
            except:
                pass

    def close(self):
        self.con.close()