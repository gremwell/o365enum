# Office 365 User Enumeration

Enumerate valid usernames from Office 365 using the office.com login page.

## Usage

o365enum will read usernames from the file provided as first parameter. The file should have one username per line.

```
python3.6 o365enum.py -h
usage: o365enum.py [-h] -u USERLIST [-v]
                 
Office365 User Enumeration Script

optional arguments:
  -h, --help            show this help message and exit
  -u USERLIST, --userlist USERLIST
                        username list one per line (default: None)
  -v, --verbose         Enable verbose output at urllib level (default: False)
```

Example run:

```
./o365enum.py -u users.txt
nonexistent@contoso.com INVALID_USER
existing@contoso.com VALID_USER
possible@federateddomain.com DOMAIN_NOT_SUPPORTED
notreal@badomain.com UNKNOWN_DOMAIN
```

## Office.com Enumeration

**WARNING**: This method only works for organization that are subscribers of Exchange Online and that do not have on-premise or hybrid deployment of Exchange server.

For companies that use on premise Exchange servers or some hybrid deployment and based on some configuration I haven't identified yet, the script will return DOMAIN_NOT_SUPPORTED.

### Existing User

When the account exists, `IfExistsResult` is set to 0, 5, or 6.

```
POST /common/GetCredentialType?mkt=en-US HTTP/1.1
Host: login.microsoftonline.com
Accept-Encoding: gzip, deflate
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36
Accept: application/json
Connection: close
client-request-id: 4345a7b9-9a63-4910-a426-35363201d503
hpgrequestid: 23975ac9-f51c-443a-8318-db006fd83100
Referer: https://login.microsoftonline.com/common/oauth2/authorize
canary: --snip--
hpgact: 1800
hpgid: 1104
Origin: https://login.microsoftonline.com
Cookie: --snip--
Content-Length: 1255
Content-Type: application/json

{
    "checkPhones": false,
    "isOtherIdpSupported": true,
    "isRemoteNGCSupported": true,
    "federationFlags": 0,
    "isCookieBannerShown": false,
    "isRemoteConnectSupported": false,
    "isSignup": false,
    "originalRequest": "rQIIA--snip--YWSO2",
    "isAccessPassSupported": true,
    "isFidoSupported": false,
    "isExternalFederationDisallowed": false,
    "username": "existing@contoso.com",
    "forceotclogin": false
}
```

```
HTTP/1.1 200 OK
Cache-Control: no-cache, no-store
Pragma: no-cache
Content-Type: application/json; charset=utf-8
Expires: -1
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
client-request-id: 177110da-7ce4-4880-b856-be6326078046
x-ms-request-id: c708b83f-4167-4b4c-a1db-d2011ecb3200
x-ms-ests-server: 2.1.9966.8 - AMS2 ProdSlices
Referrer-Policy: strict-origin-when-cross-origin
P3P: CP="DSP CUR OTPi IND OTRi ONL FIN"
Set-Cookie: fpc=ArU-Dva0f59Eg4t_V3VsX_TsYIXWAQAAAFRGxtUOAAAA; expires=Sun, 01-Mar-2020 16:01:26 GMT; path=/; secure; HttpOnly; SameSite=None
Set-Cookie: x-ms-gateway-slice=prod; path=/; SameSite=None; secure; HttpOnly
Set-Cookie: stsservicecookie=ests; path=/; secure; HttpOnly; SameSite=None
Date: Fri, 31 Jan 2020 16:01:26 GMT
Connection: close
Content-Length: 587

{
    "Username":"existing@contoso.com",
    "Display":"existing@contoso.com",
    "IfExistsResult":0,
    "ThrottleStatus":0,
    "Credentials":{
        "PrefCredential":1,
        "HasPassword":true,
        "RemoteNgcParams":null,
        "FidoParams":null,
        "SasParams":null
    },
    "EstsProperties":{
        "UserTenantBranding":null,
        "DomainType":3
    },
    "IsSignupDisallowed":true,
    "apiCanary":"--snip--"
}
```

#### Nonexistent User

When the account does not exist, `IfExistsResult` is set to 1.

```
POST /common/GetCredentialType?mkt=en-US HTTP/1.1
Host: login.microsoftonline.com
Accept-Encoding: gzip, deflate
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.88 Safari/537.36
Accept: application/json
Connection: close
client-request-id: 4345a7b9-9a63-4910-a426-35363201d503
hpgrequestid: 23975ac9-f51c-443a-8318-db006fd83100
Referer: https://login.microsoftonline.com/common/oauth2/authorize
canary: --snip--
hpgact: 1800
hpgid: 1104
Origin: https://login.microsoftonline.com
Cookie: --snip--
Content-Length: 1255
Content-Type: application/json

{
    "checkPhones": false,
    "isOtherIdpSupported": true,
    "isRemoteNGCSupported": true,
    "federationFlags": 0,
    "isCookieBannerShown": false,
    "isRemoteConnectSupported": false,
    "isSignup": false,
    "originalRequest": "rQIIA--snip--YWSO2",
    "isAccessPassSupported": true,
    "isFidoSupported": false,
    "isExternalFederationDisallowed": false,
    "username": "nonexistent@contoso.com",
    "forceotclogin": false
}
```

```
HTTP/1.1 200 OK
Cache-Control: no-cache, no-store
Pragma: no-cache
Content-Type: application/json; charset=utf-8
Expires: -1
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
client-request-id: 95bba645-c3b0-4566-b0f4-237bd3df2ca7
x-ms-request-id: fea01b74-7a60-4142-a54d-7aa8f6471c00
x-ms-ests-server: 2.1.9987.14 - WEULR2 ProdSlices
Referrer-Policy: strict-origin-when-cross-origin
P3P: CP="DSP CUR OTPi IND OTRi ONL FIN"
Set-Cookie: fpc=Ai0TKYuyz3BCp7OL29pUnG7sYIXWAQAAABsDztUOAAAA; expires=Sat, 07-Mar-2020 12:57:44 GMT; path=/; secure; HttpOnly; SameSite=None
Set-Cookie: x-ms-gateway-slice=estsfd; path=/; SameSite=None; secure; HttpOnly
Set-Cookie: stsservicecookie=ests; path=/; secure; HttpOnly; SameSite=None
Date: Thu, 06 Feb 2020 12:57:43 GMT
Connection: close
Content-Length: 579


{
    "ThrottleStatus": 0,
    "apiCanary": "--snip--",
    "Username": "nonexistent@contoso.com",
    "IfExistsResult": 1,
    "EstsProperties": {
        "UserTenantBranding": null,
        "DomainType": 3
    },
    "Credentials": {
        "PrefCredential": 1,
        "FidoParams": null,
        "RemoteNgcParams": null,
        "SasParams": null,
        "HasPassword": true
    },
    "IsSignupDisallowed": true,
    "Display": "nonexistent@contoso.com"
}
```

## Contributors

* [@jenic](https://github.com/jenic) - Arguments parsing and false negative reduction.
* [@gremwell](https://github.com/gremwell) - Original script author
