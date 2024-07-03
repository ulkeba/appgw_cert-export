import datetime
import os
import json
import base64
import requests
import cryptography
import csv 

from cryptography import x509

from azure.identity import DefaultAzureCredential

WORK_DIR = os.getcwd()
OUT_BASE_DIR = WORK_DIR + "/out"

access_token = None

def get_token():
    global access_token
    if access_token == None:
        print ('Getting token...')
        credential = DefaultAzureCredential()
        access_token = credential.get_token("https://management.azure.com/.default")
    return access_token.token

def extend_with_certificate_details(appGwJson):
    # AppGWv1 stores trusted certificates in 'authenticationCertificates'.
    if 'properties' in appGwJson and 'authenticationCertificates' in appGwJson['properties']:
        for i in appGwJson['properties']['authenticationCertificates']:
            certificate_details = get_certificate_details(i['properties']['data'])
            i['properties']['certificateDetails'] = certificate_details
    # AppGWv2 stores trusted certificates in 'trustedRootCertificates'.
    if 'properties' in appGwJson and 'trustedRootCertificates' in appGwJson['properties']:
        for i in appGwJson['properties']['trustedRootCertificates']:
            certificate_details = get_certificate_details(i['properties']['data'])
            i['properties']['certificateDetails'] = certificate_details
    return appGwJson


def get_certificate_details(certData):
    decoded_data = base64.b64decode(certData)
    try:
        decoded = decoded_data.decode('utf-8')
        format = 'utf-8/'
    except UnicodeDecodeError:
        try: 
            decoded = decoded_data.decode('utf-16')
            format = 'utf-16/'
        except UnicodeDecodeError:
            decoded = None
            format = 'bin/'

    if decoded:
        # We managed to decode to string; attempting to read PEM format.
        x509 = cryptography.x509.load_pem_x509_certificate(bytes(decoded, 'utf-8'))
        format += 'pem'
    else: 
        # We failed to decode to string; attempting to read DER format.
        x509 = cryptography.x509.load_der_x509_certificate(decoded_data)
        format += 'der'

    san = ""
    try: 
        san = x509.extensions.get_extension_for_class(cryptography.x509.SubjectAlternativeName)
    except cryptography.x509.extensions.ExtensionNotFound:
        pass

    basic = ""
    try: 
        basic = x509.extensions.get_extension_for_class(cryptography.x509.BasicConstraints)
    except cryptography.x509.extensions.ExtensionNotFound:
        pass

    return {
        'format': format,
        'issuer': x509.issuer.rfc4514_string(),
        'subject': x509.subject.rfc4514_string(),
        'issuerEqualsSubject': x509.issuer == x509.subject,
        'validFrom': x509.not_valid_before_utc.strftime('%Y-%m-%d %H:%M:%S'),
        'validTo': x509.not_valid_after_utc.strftime('%Y-%m-%d %H:%M:%S'),
        'expired': x509.not_valid_after_utc.timestamp() < datetime.datetime.now().timestamp(),
        'subjectAlternativeName': str(san.value) if san else None,
        'basicConstraints': str(basic._value) if basic else None
    }





def get_appgw_json_from_arm(appGwId):
    headers = {'Authorization': 'Bearer ' + get_token()}
    response = requests.get('https://management.azure.com' + appGwId + '?api-version=2023-09-01', headers=headers)

    if (response.status_code != 200):
        print('Failed to get appgw: ' + response.text)
        # TODO: Proper failure handling.
        exit(1)
    
    return response.text

def process_appgw(appGwSource):
    if (appGwSource.startswith('file://')):
        appGwFilePath = appGwSource[7:]
        appGwJsonString = open(appGwFilePath).read()
        appGwJson = json.loads(appGwJsonString)
        appGwId = appGwJson['id']
    else:
        appGwId = appGwSource
        appGwJsonString = get_appgw_json_from_arm(appGwId)
        appGwJson = json.loads(appGwJsonString)

    # split appGwId by '/' delimiter.
    appGwIdParts = appGwId.split('/')
    appGwSubId = appGwIdParts[2]
    appGwRgName = appGwIdParts[4]
    appGwName = appGwIdParts[8]

    os.makedirs(OUT_BASE_DIR + '/' + appGwRgName, exist_ok=True)
    appGwJsonFileName = os.path.join(OUT_BASE_DIR, appGwRgName, appGwName + '.json')
    appGwExtendedJsonFileName = os.path.join(OUT_BASE_DIR, appGwRgName, appGwName + '_extended.json')


    open(appGwJsonFileName, "w").write(appGwJsonString)
    appGwJson = extend_with_certificate_details(appGwJson)

    open(appGwExtendedJsonFileName, "w").write(json.dumps(appGwJson, indent=2))
    return unwrap_backend_settings(appGwJson)

def get_certificate_details_by_id(list, certId) -> dict:
    for c in list:
        if c['id'] == certId:
            ret_val = c['properties']['certificateDetails']
            ret_val = {**ret_val, 'name': c['name']}
            return ret_val
    # trustedRootCert = filter (lambda i: i['id'] == certId, list)
    # if trustedRootCert[0]:
    #     return trustedRootCert[0]['properties']['certificateDetails']
    return None


def get_request_routing_rules_by_id(appGwExtendedJson, id):
    ret_val = [x for x in appGwExtendedJson['properties']['requestRoutingRules'] if x['id'] == id]
    if len(ret_val) != 1:
        raise "Expected to find exactly one backendAddressPools here."
    return ret_val[0]

def get_backend_address_pool_by_id(appGwExtendedJson, id):
    ret_val = [x for x in appGwExtendedJson['properties']['backendAddressPools'] if x['id'] == id]
    if len(ret_val) != 1:
        raise "Expected to find exactly one backendAddressPools here."
    return ret_val[0]

def  unwrap_backend_settings(appGwExtendedJson):
    backendSettings = []
    for i in appGwExtendedJson['properties']['backendHttpSettingsCollection']:
        appGwId = appGwExtendedJson['id']
        appGwIdParts = appGwId.split('/')
        appGwSubId = appGwIdParts[2]
        appGwRgName = appGwIdParts[4]
        appGwName = appGwIdParts[8]
        requestRoutingRules = i['properties']['requestRoutingRules']
        addressPools = []
        for requestRoutingRuleId in requestRoutingRules:
            requestRoutingRule = get_request_routing_rules_by_id(appGwExtendedJson, requestRoutingRuleId['id'])
            backendAddressPool = get_backend_address_pool_by_id(appGwExtendedJson, requestRoutingRule['properties']['backendAddressPool']['id'])
            addressPools.append({
                'addressPoolName' : backendAddressPool['name'],
                'addressPoolAddresses': backendAddressPool['properties']['backendAddresses']
            })

        settingsBase = {
                'appGwId': appGwId,
                'subscriptionId': appGwSubId,
                'resourceGroupName': appGwRgName,
                'appGwName': appGwName,
                'appGwSku': appGwExtendedJson['properties']['sku']['name'],
                'backendHttpSettingsName': i['name'],
                'addressPools': addressPools,
                'backendHttpSettingsHostName': None if not ('hostName' in i['properties']) else i['properties']['hostName'],
                'pickHostNameFromBackendAddress': None if not ('pickHostNameFromBackendAddress' in i['properties']) else i['properties']['pickHostNameFromBackendAddress'],
            }
        
        allAuthenticationCertificates = appGwExtendedJson['properties']['authenticationCertificates'] if 'authenticationCertificates' in appGwExtendedJson['properties'] else []
        settingsAuthenticationCertificates = i['properties']['authenticationCertificates'] if 'authenticationCertificates' in i['properties'] else []
        for cert in settingsAuthenticationCertificates:
            cD = get_certificate_details_by_id(allAuthenticationCertificates, cert['id'])
            s = {
                **settingsBase, 
                'authenticationCertificateInternalName': cD['name'],
                'authenticationCertificateFormat': cD['format'],
                'authenticationCertificateIssuer': cD['issuer'],
                'authenticationCertificateSubject': cD['subject'],
                'authenticationCertificateIssuerEqualsSubject': cD['issuerEqualsSubject'],
                'authenticationCertificateValidFrom': cD['validFrom'],
                'authenticationCertificateValidTo': cD['validTo'],
                'authenticationCertificateExpired': cD['expired'],
                'authenticationCertificateSubjectAlternativeName': cD['subjectAlternativeName'],
                'authenticationCertificateBasicConstraints': cD['basicConstraints']
            }
            backendSettings.append(s)

        allTrustedRootCertificates = appGwExtendedJson['properties']['trustedRootCertificates'] if 'trustedRootCertificates' in appGwExtendedJson['properties'] else []
        settingsTrustedCertificates = i['properties']['trustedRootCertificates'] if 'trustedRootCertificates' in i['properties'] else []
        for cert in settingsTrustedCertificates:
            cD = get_certificate_details_by_id(allTrustedRootCertificates, cert['id'])
            s = {
                **settingsBase, 
                'trustedRootCertificateIssuer': cD['name'],
                'trustedRootCertificateFormat': cD['format'],
                'trustedRootCertificateIssuer': cD['issuer'],
                'trustedRootCertificateSubject': cD['subject'],
                'trustedRootCertificateIssuerEqualsSubject': cD['issuerEqualsSubject'],
                'trustedRootCertificateValidFrom': cD['validFrom'],
                'trustedRootCertificateValidTo': cD['validTo'],
                'trustedRootCertificateExpired': cD['expired'],
                'trustedRootCertificateSubjectAlternativeName': cD['subjectAlternativeName'],
                'trustedRootCertificateBasicConstraints': cD['basicConstraints']
            }
            backendSettings.append(s)

    return backendSettings


if __name__ == "__main__":

    IN_FILE = WORK_DIR + "/appgw_inventory.json"
    os.makedirs(OUT_BASE_DIR, exist_ok=True)

    allBackendSettings = []

    print(f'Opening file: {IN_FILE} for reading Application Gateway IDs...')
    with open(IN_FILE) as f:
        appGwInventory = f.read()
        appGwIds = json.loads(appGwInventory)
        for appGwId in appGwIds:
            print(f'Processing: {appGwId}...')
            backendSettings = process_appgw(appGwId)
            allBackendSettings += backendSettings
    
    allBackendSettingsJsonFileName = os.path.join(OUT_BASE_DIR, 'all_backend_settings.json')
    print(f'Writing file: {allBackendSettingsJsonFileName}...')
    open(allBackendSettingsJsonFileName, "w").write(json.dumps(allBackendSettings, indent=2))

    allBackendSettingsCsvFileName = os.path.join(OUT_BASE_DIR, 'all_backend_settings.csv')
    print(f'Writing file: {allBackendSettingsCsvFileName}...')
    with open(allBackendSettingsCsvFileName, 'w', newline='') as csvfile:
        fieldnames = []
        for i in allBackendSettings:
            fieldnames += [x for x in i.keys() if x not in fieldnames]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='raise')

        writer.writeheader()
        writer.writerows(allBackendSettings)




    

