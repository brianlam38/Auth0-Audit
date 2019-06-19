import sys
import json
import requests
import config


def getAllClients(url, api_token):
    """Get a list of all clients in a tenant and their details."""
    auth = {
        'Authorization': 'Bearer ' + api_token
    }

    res = requests.get(url + 'clients', headers=auth)

    if res.status_code != 200:
        print('Error with calling API: {}'.format(res.content))
        sys.exit(1)

    return json.loads(res.content)


def getAppType(client):
    """Get the application type for a client."""
    if 'app_type' not in client.keys():
        return 'generic'
    return client['app_type']


def showCallbacks(client):
    """Print a list of allowed callback URLs for a client."""
    if 'callbacks' in client.keys() and len(client['callbacks']) != 0:
        print('Review the list of callback URLs:')
        for url in client['callbacks']:
            print('-> {}'.format(url))


def showLogouts(client):
    """Print a list of allowed logout URLs for a client."""
    if 'logouts' in client.keys() and len(client['logouts']) != 0:
        print('Review the list of logout URLs:')
        for url in client['allowed_logout_urls']:
            print('-> {}'.format(url))


def hasImplicitGrant(client):
    """Check if a client is using the implicit grant."""
    if 'implicit' in client['grant_types']:
        return True


def hasRefreshGrant(client):
    """Check if a client is using the refresh token grant."""
    if 'refresh_token' in client['grant_types']:
        return True


def hasAuthorizationGrant(client):
    """Check if a client is using the authorization code grant."""
    if 'authorization_code' in client['grant_types']:
        return True


def hasClientCredentials(client):
    """Check if a client is using the client credentials grant."""
    if 'client_credentials' in client['grant_types']:
        return True


def hasResourceOwnerPassword(client):
    """Check if a client is using the resource owner password grant."""
    if 'password' or 'http://auth0.com/oauth/grant-type/password-realm' in client['grant_types']:
        return True


def isSecureJwtSigning(client):
    """Check if a client is using the RS256 algorithm to sign its JWTs."""
    # algorithm not specified
    if 'jwt_configuration' not in client.keys():
        return False
    if 'alg' not in client['jwt_configuration'].keys():
        return False
    # algorithm is 'HS256'
    if client['jwt_configuration']['alg'] == 'HS256':
        return False
    # algorithm is 'RS256
    return True


def isFirstParty(client):
    """Check if a client is a first-party application."""
    if 'is_first_party' in client.keys():
        return client['is_first_party']


def isOIDCConformant(client):
    """Check if a client is OIDC Conformant."""
    if 'oidc_conformant' in client.keys():
        return client['oidc_conformant']


if __name__ == '__main__':
    # Pipelines test
    if config.ENVIRONMENT == 'test':
        with open('tests/test.json', 'r') as f:
            clients = json.loads(f.read())
    # Ansarada dev tenant
    elif config.ENVIRONMENT == 'dev':
        url = config.AUTH0_DEV_URL
        api_token = config.AUTH0_DEV_TOKEN
        clients = getAllClients(url, api_token)
    # Ansarada prod tenant
    elif config.ENVIRONMENT == 'prod':
        url = config.AUTH0_PROD_URL
        api_token = config.AUTH0_PROD_TOKEN
        clients = getAllClients(url, api_token)
    else:
        print('Please set variable "ENVIRONMENT" in config.py')
        sys.exit(1)

    with open('checklist.json', 'r') as f:
        checklist = json.loads(f.read())
    
        # Audit clients
        for i, c in enumerate(clients):
            print('\n({}) Client: {}'.format(i, c['name']))
            print('Security Recommendations:')
            findings = []

            # Perform audit
            if hasImplicitGrant(c): findings.append(checklist['check_grant_implicitnotused'])
            if hasRefreshGrant(c): findings.append(checklist['check_grant_refreshnotused'])
            if not isSecureJwtSigning(c): findings.append(checklist['check_algorithm'])
            if not isFirstParty(c) and hasResourceOwnerPassword(c): findings.append(checklist['check_apptype_thirdpartynotusepassword'])
            if not isOIDCConformant(c): findings.append(checklist['check_oidcconformant'])
            if getAppType(c) == 'generic': findings.append(checklist['check_apptype_genericnotused'])
            if getAppType(c) == 'webapp' and not hasAuthorizationGrant(c): findings.append(checklist['check_apptype_webapphasauthcode'])
            if getAppType(c) == 'm2m' and not hasClientCredentials(c): findings.append(checklist['check_apptype_m2mhasclientcred'])

            # Process warnings
            if len(findings) == 0:
                print('-> Configuration is secure.')
            for f in findings:
                print('-> Warning: {}'.format(f))
                
            # Print callback and logout URLs
            showCallbacks(c)
            showLogouts(c)