#!/usr/bin/env python3
'''
Office365 User Enumeration script.
Enumerate valid usernames from Office 365 using ActiveSync or office.com login page.

Author: Quentin Kaiser <quentin@gremwell.com>
'''
import random
import re
import string
import sys
import requests
import argparse
import logging

try:
    import http.client as http_client
except ImportError:
    import httplib as http_client

def load_usernames(usernames_file):
    '''
    Loads a list of usernames from `usernames_file`.

    Args:
        usernames_file(str): filename of file holding usernames

    Returns:
        usernames(list): a list of usernames
    '''
    with open(usernames_file) as file_handle:
        return [line.strip() for line in file_handle.readlines()]

def o365enum_activesync(usernames):
    '''
    Check if `usernames` exists using ActiveSync.

    Args:
        usernames(list): list of usernames to enumerate
    '''
    headers = {
        "MS-ASProtocolVersion": "14.0",
        "User-Agent": "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.12026; Pro"
    }
    for username in usernames:
        state = 0
        for x in range(0, args.num):
            response = requests.options(
                "https://outlook.office365.com/Microsoft-Server-ActiveSync",
                headers=headers,
                auth=(username, args.password)
            )

            if response.status_code == 200:
                print(f'{username},2')
                state = 1
                break
            else:
                if 'X-MailboxGuid' in response.headers:
                    print("{},{}".format(username, 1))
                    state = 1
                    break
                else:
                    state = 0

        if state == 0:
            print("{},{}".format(username,0))

def o365enum_office(usernames):
    '''
    Checks if `usernames` exists using office.com method.

    Args:
        usernames(list): list of usernames to enumerate
    '''
    headers = {
        "User-Agent":"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"\
            " (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36"
    }
    # first we open office.com main page
    session = requests.session()
    response = session.get(
        "https://www.office.com",
        headers=headers
    )
    # we get the application identifier and session identifier
    client_id = re.findall(b'"appId":"([^"]*)"', response.content)
    # then we request the /login page which will redirect us to the authorize
    # flow
    response = session.get(
        "https://www.office.com/login?es=Click&ru=/&msafed=0",
        headers=headers,
        allow_redirects=True
    )
    hpgid = re.findall(b'hpgid":([0-9]+),', response.content)
    hpgact = re.findall(b'hpgact":([0-9]+),', response.content)

    if not client_id or not hpgid or not hpgact:
        raise Exception("An error occured when generating headers.")

    # we setup the right headers to blend in
    headers['client-request-id'] = client_id[0]
    headers['Referer'] = response.url
    headers['hpgrequestid'] = response.headers['x-ms-request-id']
    headers['canary'] = ''.join(
        random.choice(
            string.ascii_uppercase + string.ascii_lowercase + string.digits + "-_"
        ) for i in range(248)
    )
    headers['hpgid'] = hpgid[0]
    headers['Accept'] = "application/json"
    headers['hpgact'] = hpgact[0]
    headers['Origin'] = "https://login.microsoftonline.com"

    # we setup the base JSON object to submit
    payload = {
        "isOtherIdpSupported":True,
        "checkPhones":False,
        "isRemoteNGCSupported":True,
        "isCookieBannerShown":False,
        "isFidoSupported":False,
        "originalRequest": re.findall(b'"sCtx":"([^"]*)"', response.content)[0].decode('utf-8'),
        "forceotclogin":False,
        "isExternalFederationDisallowed":False,
        "isRemoteConnectSupported":False,
        "federationFlags":0,
        "isSignup":False,
        "isAccessPassSupported":True
    }

    for username in usernames:
        payload["username"] = username
        response = session.post(
            "https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US",
            headers=headers,
            json=payload
        )
        if response.status_code == 200:
            exists = not int(response.json()['IfExistsResult'])
        else:
            exists = -1
        print("{},{}".format(username, int(exists)))

def o365enum(usernames, method="activesync"):
    '''
    Enumerate usernames using either ActiveSync or Office.com.
    '''
    print("username,valid")
    if method == "activesync":
        o365enum_activesync(usernames)
    elif method == "office.com":
        o365enum_office(usernames)
    else:
        raise Exception("Invalid method provided.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
            description='Rebuild username enum')
    parser.add_argument('-u', '--userlist', required=True, type=str,
            help='username list one per line')
    parser.add_argument('-p', '--password', default='Password1', type=str,
            help='password to try')
    parser.add_argument('-n', '--num', default=3, type=int,
            help='# of reattempts to remove false negatives')
    parser.add_argument('-v', '--verbose', default=False, action='store_true',
            help='Enable verbose output at urllib level')
    parser.add_argument('-m', '--method', default='activesync', type=str,
            choices=('activesync', 'office.com'),
            help='method to use')
    args = parser.parse_args()

    if args.verbose:
        http_client.HTTPConnection.debuglevel = 1
        logging.basicConfig(
                format="%(asctime)s: %(levelname)s: %(module)s: %(message)s")
        logging.getLogger().setLevel(logging.DEBUG)
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True

    o365enum(load_usernames(args.userlist), args.method)
