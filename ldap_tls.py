# --*-- coding:utf-8 --*--
import argparse
import random
import subprocess
from ldap3.core.exceptions import LDAPBindError, LDAPException
from xpinyin import Pinyin
from ldap3 import *

ADMIN = 'cn=admin,dc=edf,dc=com'
ADMIN_PWD = 'xxxxxxx'
SERVER = 'ldap://x.x.x.x:389'
SEARCH = 'dc=xxx,dc=edf,dc=com'
OU = 'users'


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
            return secret

    def connect_ldap_server(self):
        # connect ldap server with tls
        try:
            cu_tls = Tls()
            server_uri = SERVER
            server = Server(server_uri, get_info=ALL, use_ssl=False, tls=cu_tls)
            connection = Connection(server,
                                    user=ADMIN,
                                    password=ADMIN_PWD)
            connection.start_tls()
            bind_response = connection.bind()  # Returns True or False
            if bind_response:
                return connection
            else:
                raise Exception("bind error!connect to ldap failed!")
        except LDAPBindError as e:
            raise Exception(e)

    def get_users(self, username, ldap_conn):
        search_base = SEARCH
        search_filter = f'(cn={username})'

        try:
            ldap_conn.search(search_base=search_base,
                             search_filter=search_filter,
                             search_scope=SUBTREE,
                             attributes=['cn', 'sn', 'uid', 'uidNumber'])

            results = ldap_conn.entries
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
        print("Delete success!")

    def mod_passwd(self, user, new_pwd, ldap_conn):
        with open("ldap_cu/tmp/secret", 'w', encoding='utf-8') as fp:
            fp.write(new_pwd)
        pwd_hash = self.gen_pwd_hash()
        users = self.get_users(user, ldap_conn)
        for i in users:

            dn = str(i).split('\n')[0].split(' ')[1].strip()
            res = ldap_conn.modify(dn, {'userPassword': [(MODIFY_REPLACE, [pwd_hash])]})
            if not res:
                return 'error'
            else:
                print(f'username:{user},password:{new_pwd}')

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

        add_res = conn.add(f'cn={user},ou={ou},{SEARCH}',
                           ['inetOrgPerson', 'organizationalPerson', 'top', 'person', 'shadowAccount'],
                           {'uid': f'{user}', 'mail': f'{user}@baidu.com', 'sn': 'Person', 'cn': f'{user}',
                            'userPassword': f'{pwd_hash}'})
        return add_res
        # with open('ldap_cu/conf/user.ldif', 'w', encoding='utf-8') as fp:
        #     fp.writelines(lines)
        # out = subprocess.getoutput('/bin/bash ldap_cu/script/add.sh')

    def get_group(self, dn_name, ldap_conn):
        search_base = SEARCH
        search_filter = f'(cn={dn_name})'

        try:
            ldap_conn.search(search_base=search_base,
                             search_filter=search_filter,
                             search_scope=SUBTREE,
                             attributes=['cn', 'objectClass', 'member'])

            results = ldap_conn.entries
            return results
        except LDAPException as e:
            raise Exception(e)

    def get_dn(self, cn):
        return str(cn).split('\n')[0].split(' - ')[0].split(':')[1].strip()

    def mod_group(self, user, group, action, ldap_conn):
        actions = ['add', 'del']
        if action not in actions:
            raise BaseException('action illegal!')
        gourp_dns = self.get_users(group, ldap_conn)
        users = self.get_users(user, ldap_conn)
        tcn = ''
        for i in gourp_dns:
            if 'groups' in str(i):
                tcn = i
                break
        gcn = self.get_dn(tcn)

        if users:
            dn = str(self.get_dn(users[0]))
        else:
            raise BaseException('user not found')
        if action == 'add':
            print(dn)
            print(gcn)

            res = ldap_conn.modify(gcn, {'member': [(MODIFY_ADD, dn)]})
        if action == 'del':
            res = ldap_conn.modify(gcn, {'member': [(MODIFY_DELETE, dn)]})
        if not res:
            print('user not in vpn group!')
        else:
            print('Operation success!')



if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--action')
    parser.add_argument('-n', '--name')
    parser.add_argument('-p', '--password')
    parser.add_argument('-g', '--group')
    parser.add_argument('-ga', '--group_action')
    args = parser.parse_args()
    action = args.action
    group_action = args.group_action
    name = args.name
    group = args.group
    password = args.password
    ldap = Mgmt_ldap()
    conn = ldap.connect_ldap_server()
    if action == 'add':
        password = ldap.gen_pwd(name, OU)
        hash_pwd = ldap.gen_pwd_hash()
        res = ldap.add_user(OU, name, hash_pwd, conn)
        if group:
            ldap.mod_group(name, 'vpn', 'add', conn)
        if res:
            print(f'add success! username:{name},password:{password}')
    elif action == 'del':
        ldap.mod_group(name, 'vpn', 'del', conn)
        ldap.delete_users(name, conn)
    elif action == 'mod' and not group:
        ldap.mod_passwd(name, password, conn)
    elif action == 'mod' and group and group_action:
        ldap.mod_group(name, group, group_action, conn)
