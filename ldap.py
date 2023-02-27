# --*-- coding:utf-8 --*--
import argparse
import random
import subprocess
from ldap3.core.exceptions import LDAPBindError, LDAPException
from xpinyin import Pinyin
from ldap3 import *

ADMIN = 'cn=admin,dc=abc,dc=com'
ADMIN_PWD = 'xxxxx'
SERVER = 'ldap://x.x.x.x:389'
SEARCH = 'dc=abc,dc=com'


class Mgmt_ldap:
    def gen_pwd_hash(self):
        with open('ldap_cu/tmp/secret', 'r', encoding='utf-8') as fp:
            line = fp.readline()
        if line:
            output = subprocess.getoutput(f'slappasswd -T ldap_cu/tmp/secret')
        return output.split('\n')[1]

    def gen_pwd(self, name, ou):
        seed = 'q a z w s x e d c 1 2 3 4 5 6 7 8 9 0 t'
        seeds = seed.split(' ')
        secret = ''
        for i in range(0, 8):
            secret = secret + random.choice(seeds)
        with open('ldap_cu/tmp/secret', 'w', encoding='utf-8') as fp:
            fp.write(secret)
        with open('user-pwd.txt', 'a', encoding='utf-8') as pf:
            pf.write(f"{ou} {name}  username:{self.get_pinyin(name)} password:{secret}\n")

    def connect_ldap_server(self):
        try:
            # Provide the hostname and port number of the openLDAP
            server_uri = SERVER
            server = Server(server_uri, get_info=ALL)
            # username and password can be configured during openldap setup
            connection = Connection(server,
                                    user=ADMIN,
                                    password=ADMIN_PWD)
            bind_response = connection.bind()  # Returns True or False
            if bind_response:
                return connection
            else:
                raise Exception("bind error!connect to ldap failed!")
        except LDAPBindError as e:
            raise Exception(e)

    def add_user_to_group(self, conn):
        print(self.get_users('aa', conn))

    def get_users(self, username, ldap_conn):
        search_base = SEARCH
        search_filter = f'(cn={username})'

        try:
            ldap_conn.search(search_base=search_base,
                             search_filter=search_filter,
                             search_scope=SUBTREE,
                             attributes=['cn', 'sn', 'uid', 'uidNumber'])

            results = ldap_conn.entries
            print(results)
            return results
        except LDAPException as e:
            raise Exception(e)

    def delete_users(self, user, ldap_conn):
        users = self.get_users(user, ldap_conn)
        res = ''
        for i in users:
            i = str(i)
            dn = i.split('\n')[0].split(" ")[1]
            try:
                response = ldap_conn.delete(dn=f'{dn}')
                res = response
            except LDAPException as e:
                raise Exception(e)
        lines_without_user = []
        if res:
            with open('user-pwd.txt', 'r', encoding='utf-8') as pf:
                lines = pf.readlines()
                for j in lines:
                    if user not in j:
                        lines_without_user.append(j)
            with open('user-pwd.txt', 'w', encoding='utf-8') as fp:
                fp.writelines(lines_without_user)

    def mod_passwd(self, user, new_pwd, ldap_conn):
        with open("ldap_cu/tmp/secret", 'w', encoding='utf-8') as fp:
            fp.write(new_pwd)
        pwd_hash = self.gen_pwd_hash()
        users = self.get_users(user, ldap_conn)
        for i in users:
            dn = str(i).split('\n')[0].split(' - ')[0].split(':')[1].strip()
            print(dn + "------dn")
            res = ldap_conn.modify(dn, {'userPassword': [(MODIFY_REPLACE, [pwd_hash])]})
            if not res:
                return 'error'

    def get_dn(self, cn):
        return str(cn).split('\n')[0].split('-')[0].split(':')[1].strip()

    def mod_group(self, user, gourp, action, ldap_conn):
        actions = ['add', 'del']
        if action not in actions:
            raise BaseException('action illegal!')
        gourp_dn = self.get_users(gourp, ldap_conn)
        users = self.get_users(user, ldap_conn)
        if users:
            dn = str(users[0]).split('\n')[0].split('-')[0].split(':')[1].strip()
        else:
            raise BaseException('user not found')
        if action == 'add':
            ldap_conn.modify(self.get_dn(gourp_dn), {'member': [(MODIFY_ADD, dn)]})
        if action == 'del':
            ldap_conn.modify(self.get_dn(gourp_dn), {'member': [(MODIFY_DELETE, dn)]})

    def get_pinyin(self, user):
        pinyin = Pinyin()
        pin_yin = pinyin.get_pinyin(user)
        pin = pin_yin.replace('-', '')
        return pin

    def add_user(self, ou, user, pwd_hash, conn):

        user = self.get_pinyin(user)
        users = self.get_users(user, conn)
        for i in users:
            if i.cn == user:
                raise Exception('username exsited, add failed')

        add_res = conn.add(f'uid={user},ou={ou},{SEARCH}',
                           ['inetOrgPerson', 'posixAccount', 'shadowAccount'],
                           {'sn': 'Person', 'cn': f'{user}', 'userPassword': f'{pwd_hash}',
                            'uidNumber': 2000, 'gidNumber': 2000, 'loginShell': '/bin/bash',
                            'homeDirectory': f'/home/{user}'})
        return add_res


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--action')
    parser.add_argument('-n', '--name')
    parser.add_argument('-o', '--ou')
    parser.add_argument('-p', '--password')
    args = parser.parse_args()
    action = args.action
    name = args.name
    ou = args.ou
    password = args.password
    ldap = Mgmt_ldap()
    conn = ldap.connect_ldap_server()

    if action == 'add':
        ldap.gen_pwd(name, ou)
        hash_pwd = ldap.gen_pwd_hash()
        res = ldap.add_user(ou, name, hash_pwd, conn)
        print(res)
    elif action == 'del':
        ldap.delete_users(name, conn)
    elif action == 'mod':
        ldap.mod_passwd(name, password, conn)
