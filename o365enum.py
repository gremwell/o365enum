#!/usr/bin/env python3
'''
Office365 User Enumeration script.
Enumerate valid usernames from Office 365 using the office.com login page.

Author: Quentin Kaiser <quentin@gremwell.com>
Author: Cameron Geehr @BTit0r
'''
import random
import re
import string
import argparse
import logging
import requests
import xml.etree.ElementTree as ET 

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

    environments = dict()
    for username in usernames:
        # Check to see if this domain has already been checked
        # If it's managed, it's good to go and we can proceed
        # If it's anything else, don't bother checking
        domain = username.split("@")[1]
        if not domain in environments:
            url = 'https://login.microsoftonline.com/getuserrealm.srf?login={}&xml=1'.format(username)
            resp = requests.get(url)
            xmlroot = ET.fromstring(resp.content)
            environments[domain] = xmlroot[3].text
        
        if environments[domain] == "Managed":
            payload["username"] = username
            response = session.post(
                "https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US",
                headers=headers,
                json=payload
            )
            if response.status_code == 200:
                throttleStatus = int(response.json()['ThrottleStatus'])
                ifExistsResult = str(response.json()['IfExistsResult'])
                
                # NotThrottled:0,AadThrottled:1,MsaThrottled:2
                if not throttleStatus == 0:
                    print("POSSIBLE THROTTLE DETECTED ON REQUEST FOR {}".format(username))
                # Unknown:-1,Exists:0,NotExist:1,Throttled:2,Error:4,ExistsInOtherMicrosoftIDP:5,ExistsBothIDPs:6
                ifExistsResultCodes = {"-1": "UNKNOWN", "0": "VALID_USER", "1": "INVALID_USER", "2": "THROTTLE", "4": "ERROR", "5": "VALID_USER", "6": "VALID_USER"}
                print("{} {}".format(username, ifExistsResultCodes[ifExistsResult]))
            else:
                print("{} REQUEST_ERROR".format(username))
        elif environments[domain] == "Federated":
            print("{} DOMAIN_NOT_SUPPORTED".format(username))
        else:
            print("{} UNKNOWN_DOMAIN".format(username))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        description='Office365 User Enumeration Script')
    parser.add_argument('-u', '--userlist', required=True, type=str,\
        help='username list one per line')
    parser.add_argument('-v', '--verbose', default=False, action='store_true',\
        help='Enable verbose output at urllib level')
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

    o365enum_office(load_usernames(args.userlist))

