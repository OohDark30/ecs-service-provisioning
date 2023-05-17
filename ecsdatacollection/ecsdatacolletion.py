"""
DELL Object Service Provisioning - Data Collection
"""
import io
import os
import json
import requests
import urllib3
import uuid
from requests.auth import HTTPBasicAuth

# Constants
MODULE_NAME = "ecs"                  # Module Name

class ECSException(Exception):
    pass


class ECSAuthentication(object):
    """
    Stores ECS Authentication Information
    """
    def __init__(self, protocol, host, username, password, port, logger):
        self.protocol = protocol
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.logger = logger
        self.logger.info('ECSAuthentication::Object instance initialization complete.')
        self.url = "{0}://{1}:{2}".format(self.protocol, self.host, self.port)
        self.token = ''

        # Disable warnings
        urllib3.disable_warnings()

    def get_url(self):
        """
        Returns an ECS Management url made from protocol, host and port.
        """
        return self.url

    def get_token(self):
        """
        Returns an ECS Management token
        """
        return self.tokens

    def connect(self):
        """
        Connect to ECS and if successful update token
        """
        self.logger.info('ECSAuthentication::connect()::We are about to attempt to connect to ECS with the following URL : '
                         + "{0}://{1}:{2}".format(self.protocol, self.host, self.port) + '/login')

        r = requests.get("{0}://{1}:{2}".format(self.protocol, self.host, self.port) + '/login',
                         verify=False, auth=HTTPBasicAuth(self.username, self.password))

        self.logger.info('ECSAuthentication::connect()::login call to ECS returned with status code: ' + str(r.status_code))
        if r.status_code == requests.codes.ok:
            self.logger.debug('ECSAuthentication::connect()::login call returned with a 200 status code.  '
                              'X-SDS-AUTH-TOKEN Header contains: ' + r.headers['X-SDS-AUTH-TOKEN'])
            self.token = r.headers['X-SDS-AUTH-TOKEN']
        else:
            self.logger.error('ECSManagementAPI::connect()::login call '
                             'failed with a status code of ' + str(r.status_code))
            self.token = None


class ECSManagementAPI(object):
    """
    Perform ECS Management API Calls
    """

    def __init__(self, authentication, logger, response_json=None, response_xml=None):
        self.ecs_authentication_failure = int('497')
        self.authentication = authentication
        self.response_json = response_json
        self.response_xml = response_xml
        self.logger = logger
        self.response_xml_file = None

    def ecs_collect_alert_data(self, tempdir, marker):

        while True:
            # Perform ECS Dashboard Alert API Call
            headers = {'X-SDS-AUTH-TOKEN': "'{0}'".format(self.authentication.token),
                       'content-type': 'application/json'}

            # Setup parameters - WE ONLY TAKE ALERTS THAT HAVE NOT BEEN ACKNOWLEDGED
            if marker:
                params_dict = {'acknowledged': False}
                params_dict["marker"] = marker
            else:
                params_dict = {'acknowledged': False}

            # Call API
            r = requests.get("{0}//vdc/alerts".format(self.authentication.url),
                             headers=headers, verify=False, params=params_dict)

            if r.status_code == requests.codes.ok:
                self.logger.debug('ECSManagementAPI::ecs_collect_alert_data()::/vdc/alerts call returned '
                                  'with a 200 status code.  Text is: ' + r.text)

                # Create a unique temp file and store the XML to it for processing
                tempfile = os.path.abspath(os.path.join(tempdir, str(uuid.uuid4()) + ".xml"))
                fo = open(tempfile, "w+")
                fo.write(r.text)

                # Close file
                fo.close()

                self.logger.debug('ECSManagementAPI::ecs_collect_alert_data()::r.text() contains: \n' + r.text)

                self.response_xml_file = tempfile
                break
            else:
                if r.status_code == self.ecs_authentication_failure:
                    # Attempt to re-authenticate
                    self.authentication.token = None
                    self.authentication.connect()

                    if self.authentication.token is None:
                        self.logger.error('ECSManagementAPI::ecs_collect_alert_data()::Token Expired.  Unable '
                                          'to re-authenticate to ECS as configured.  Please validate and try again.')
                        raise ECSException("The ECS Data Collection Module was unable to re-authenticate.")
                        break
                else:
                    self.logger.error('ECSManagementAPI::ecs_collect_alert_data()::/vdc/alerts call failed '
                                      'with a status code of ' + str(r.status_code))
                    self.response_xml_file = None
                    break

        return self.response_xml_file

    def ecs_acknowledge_alert(self, alert_id):

        while True:
            # Perform ECS Dashboard Alert Acknowledge API Call
            headers = {'X-SDS-AUTH-TOKEN': "'{0}'".format(self.authentication.token),
                       'content-type': 'application/json'}

            r = requests.put("{0}//vdc/alerts/{1}/acknowledgment".format(self.authentication.url, alert_id),
                             headers=headers, verify=False)

            if r.status_code == requests.codes.ok:
                self.logger.debug('ECSManagementAPI::ecs_acknowledge_alert()::/vdc/alerts/acknowledgment call returned '
                                  'with a 200 status code.  Text is: ' + r.text)

                alert_acknowledged = True
                break
            else:
                if r.status_code == self.ecs_authentication_failure:
                    # Attempt to re-authenticate
                    self.authentication.token = None
                    self.authentication.connect()

                    if self.authentication.token is None:
                        self.logger.error('ECSManagementAPI::ecs_collect_alert_data()::Token Expired.  Unable '
                                          'to re-authenticate to ECS as configured.  Please validate and try again.')
                        alert_acknowledged = False
                        raise ECSException("The ECS Data Collection Module was unable to re-authenticate.")

                else:
                    self.logger.error('ECSManagementAPI::ecs_collect_alert_data()::/vdc/alerts/latest call failed '
                                      'with a status code of ' + str(r.status_code))
                    alert_acknowledged = False
                    break

        return alert_acknowledged

    def get_namespace_details(self, namespace):

        while True:
            # Perform ECS Object Namespace API Call
            headers = {'X-SDS-AUTH-TOKEN': "'{0}'".format(self.authentication.token),
                       'content-type': 'application/json', 'Accept': 'application/json'}

            r = requests.get("{0}//object/namespaces/namespace/{1}".format(self.authentication.url,namespace),
                             headers=headers, verify=False)

            if r.status_code == requests.codes.ok:
                self.logger.debug('ECSManagementAPI::get_namespace_details()::'
                                  '/object/namespaces call returned '
                                  'with a 200 status code.  Text is: ' + r.text)
                self.response_json = r.json()

                self.logger.debug('ECSManagementAPI::get_namespace_details()::r.text() contains: \n' + r.text)

                if type(self.response_json) is list:
                    self.logger.debug('ECSManagementAPI::get_namespace_details()::r.json() returned a list. ')
                elif type(self.response_json) is dict:
                    self.logger.debug('ECSManagementAPI::get_namespace_details()::r.json() returned a dictionary. ')
                else:
                    self.logger.debug('ECSManagementAPI::get_namespace_details()::r.json() returned unknown. ')
                break
            else:
                if r.status_code == self.ecs_authentication_failure:
                    # Attempt to re-authenticate
                    self.authentication.token = None
                    self.authentication.connect()

                    if self.authentication.token is None:
                        self.logger.error('ECSManagementAPI::get_namespace_details()::Token Expired.  Unable '
                                          'to re-authenticate to ECS as configured.  Please validate and try again.')
                        raise ECSException("The ECS Data Collection Module was unable to re-authenticate.")
                        break
                else:
                    self.logger.error('ECSManagementAPI::get_namespace_details()::/object/namespaces '
                                      'call against host ' + self.authentication.host + ' failed with a status code of ' + str(r.status_code))
                    self.response_json = None
                    break
        return self.response_json

    def create_namespace_admin(self, admin_user):

        while True:
            # Perform ECS Object Namespace API Call
            headers = {'X-SDS-AUTH-TOKEN': "'{0}'".format(self.authentication.token),
                       'content-type': 'application/json', 'Accept': 'application/json'}

            # Build JSON for request
            r = requests.post("{0}//vdc/users".format(self.authentication.url),
                             headers=headers, verify=False, json={'userId': admin_user, 'password': 'ChangeMe', 'isSystemAdmin': 'false', 'isSystemMonitor': 'false', 'isSecurityAdmin': 'false'})

            if r.status_code == requests.codes.ok:
                self.logger.debug('ECSManagementAPI::create_namespace_admin()::'
                                  '/vdc/users call returned '
                                  'with a 200 status code.  Text is: ' + r.text)
                self.response_json = r.json()

                self.logger.debug('ECSManagementAPI::create_namespace_admin()::r.text() contains: \n' + r.text)

                if type(self.response_json) is list:
                    self.logger.debug('ECSManagementAPI::create_namespace_admin()::r.json() returned a list. ')
                elif type(self.response_json) is dict:
                    self.logger.debug('ECSManagementAPI::create_namespace_admin()::r.json() returned a dictionary. ')
                else:
                    self.logger.debug('ECSManagementAPI::create_namespace_admin()::r.json() returned unknown. ')
                break
            else:
                if r.status_code == self.ecs_authentication_failure:
                    # Attempt to re-authenticate
                    self.authentication.token = None
                    self.authentication.connect()

                    if self.authentication.token is None:
                        self.logger.error('ECSManagementAPI::create_namespace_admin()::Token Expired.  Unable '
                                          'to re-authenticate to ECS as configured.  Please validate and try again.')
                        raise ECSException("The ECS Data Collection Module was unable to re-authenticate.")
                        break
                else:
                    self.logger.error('ECSManagementAPI::create_namespace_admin()::/vdc/users '
                                      'call against host ' + self.authentication.host + ' failed with a status code of ' + str(r.status_code))
                    self.response_json = None
                    break
        return self.response_json

    def create_namespace(self, namespace, admin_user, replication_group_id):

        while True:
            # Perform ECS Object Namespace API Call
            headers = {'X-SDS-AUTH-TOKEN': "'{0}'".format(self.authentication.token),
                       'content-type': 'application/json', 'Accept': 'application/json'}

            # Build JSON for request
            r = requests.post("{0}//object/namespaces/namespace".format(self.authentication.url),
                             headers=headers, verify=False, json={'namespace': namespace, 'namespace_admins': admin_user, 'is_stale_allowed': 'true', 'default_data_services_vpool': replication_group_id})

            if r.status_code == requests.codes.ok:
                self.logger.debug('ECSManagementAPI::create_namespace()::'
                                  '/object/namespaces/namespace call returned '
                                  'with a 200 status code.  Text is: ' + r.text)
                self.response_json = r.json()

                self.logger.debug('ECSManagementAPI::create_namespace()::r.text() contains: \n' + r.text)

                if type(self.response_json) is list:
                    self.logger.debug('ECSManagementAPI::create_namespace()::r.json() returned a list. ')
                elif type(self.response_json) is dict:
                    self.logger.debug('ECSManagementAPI::create_namespace()::r.json() returned a dictionary. ')
                else:
                    self.logger.debug('ECSManagementAPI::create_namespace()::r.json() returned unknown. ')
                break
            else:
                if r.status_code == self.ecs_authentication_failure:
                    # Attempt to re-authenticate
                    self.authentication.token = None
                    self.authentication.connect()

                    if self.authentication.token is None:
                        self.logger.error('ECSManagementAPI::create_namespace()::Token Expired.  Unable '
                                          'to re-authenticate to ECS as configured.  Please validate and try again.')
                        raise ECSException("The ECS Data Collection Module was unable to re-authenticate.")
                        break
                else:
                    self.logger.error('ECSManagementAPI::create_namespace()::/object/namespaces/namespace '
                                      'call against host ' + self.authentication.host + ' failed with a status code of ' + str(r.status_code))
                    self.response_json = None
                    break
        return self.response_json

    def update_namespace_quota(self, namespace, namespace_quota):

        while True:
            # Perform ECS Object Namespace API Call
            headers = {'X-SDS-AUTH-TOKEN': "'{0}'".format(self.authentication.token),
                       'content-type': 'application/xml', 'Accept': 'application/json'}

            quota = str(namespace_quota)

            xml_body = """
                <?xml version="1.0" encoding="UTF-8" ?>
                <namespace_quota_details>
                <blockSize>""" + quota + """</blockSize>
                <notificationSize>""" + quota + """</notificationSize>
                </namespace_quota_details>"""

            # Build JSON for request
            r = requests.post("{0}//object/namespaces/namespace/{1}/quota".format(self.authentication.url, namespace),
                              headers=headers, verify=False, data=xml_body)


            if r.status_code == requests.codes.ok:
                self.logger.debug('ECSManagementAPI::update_namespace_quota()::'
                                  '/object/namespaces/namespace/{1}/quota call returned '
                                  'with a 200 status code.  Text is: ' + r.text)
                self.response_json = r.json()

                self.logger.debug('ECSManagementAPI::update_namespace_quota()::r.text() contains: \n' + r.text)

                if type(self.response_json) is list:
                    self.logger.debug('ECSManagementAPI::update_namespace_quota()::r.json() returned a list. ')
                elif type(self.response_json) is dict:
                    self.logger.debug('ECSManagementAPI::update_namespace_quota()::r.json() returned a dictionary. ')
                else:
                    self.logger.debug('ECSManagementAPI::update_namespace_quota()::r.json() returned unknown. ')
                break
            else:
                if r.status_code == self.ecs_authentication_failure:
                    # Attempt to re-authenticate
                    self.authentication.token = None
                    self.authentication.connect()

                    if self.authentication.token is None:
                        self.logger.error('ECSManagementAPI::update_namespace_quota()::Token Expired.  Unable '
                                          'to re-authenticate to ECS as configured.  Please validate and try again.')
                        raise ECSException("The ECS Data Collection Module was unable to re-authenticate.")
                        break
                else:
                    self.logger.error('ECSManagementAPI::update_namespace_quota()::/object/namespaces/namespace/{1}/quota '
                                      'call against host ' + self.authentication.host + ' failed with a status code of ' + str(r.status_code))
                    self.response_json = None
                    break
        return self.response_json

    def create_object_user(self, namespace, object_user):

        while True:
            # Perform ECS Object Namespace API Call
            headers = {'X-SDS-AUTH-TOKEN': "'{0}'".format(self.authentication.token),
                       'content-type': 'application/json', 'Accept': 'application/json'}

            # Build JSON for request
            r = requests.post("{0}//object/users".format(self.authentication.url),
                             headers=headers, verify=False, json={'namespace': namespace, 'user': object_user})

            if r.status_code == requests.codes.ok:
                self.logger.debug('ECSManagementAPI::create_object_user()::'
                                  '/object/users call returned '
                                  'with a 200 status code.  Text is: ' + r.text)
                self.response_json = r.json()

                self.logger.debug('ECSManagementAPI::create_object_user()::r.text() contains: \n' + r.text)

                if type(self.response_json) is list:
                    self.logger.debug('ECSManagementAPI::create_object_user()::r.json() returned a list. ')
                elif type(self.response_json) is dict:
                    self.logger.debug('ECSManagementAPI::create_object_user()::r.json() returned a dictionary. ')
                else:
                    self.logger.debug('ECSManagementAPI::create_object_user()::r.json() returned unknown. ')
                break
            else:
                if r.status_code == self.ecs_authentication_failure:
                    # Attempt to re-authenticate
                    self.authentication.token = None
                    self.authentication.connect()

                    if self.authentication.token is None:
                        self.logger.error('ECSManagementAPI::create_object_user()::Token Expired.  Unable '
                                          'to re-authenticate to ECS as configured.  Please validate and try again.')
                        raise ECSException("The ECS Data Collection Module was unable to re-authenticate.")
                        break
                else:
                    self.logger.error('ECSManagementAPI::create_object_user()::/object/users '
                                      'call against host ' + self.authentication.host + ' failed with a status code of ' + str(r.status_code))
                    self.response_json = None
                    break
        return self.response_json

    def create_iam_user(self, namespace, iam_user, iam_policy):

        while True:
            # Perform ECS IAM Create User call
            headers = {'X-SDS-AUTH-TOKEN': "'{0}'".format(self.authentication.token),
                       'content-type': 'application/json', 'Accept': 'application/json', 'x-emc-namespace': namespace}

            # Create query parameters
            query_parameters = {'UserName': iam_user, 'PermissionsBoundary': iam_policy}

            # Build JSON for request
            r = requests.post("{0}//iam?Action=CreateUser".format(self.authentication.url),
                              headers=headers, verify=False, params=query_parameters)

            if r.status_code == requests.codes.ok:
                self.logger.debug('ECSManagementAPI::create_iam_user()::'
                                  '/iam?Action=CreateUser call returned '
                                  'with a 200 status code.  Text is: ' + r.text)
                self.response_json = r.json()

                self.logger.debug('ECSManagementAPI::create_iam_user()::r.text() contains: \n' + r.text)

                if type(self.response_json) is list:
                    self.logger.debug('ECSManagementAPI::create_iam_user()::r.json() returned a list. ')
                elif type(self.response_json) is dict:
                    self.logger.debug('ECSManagementAPI::create_iam_user()::r.json() returned a dictionary. ')
                else:
                    self.logger.debug('ECSManagementAPI::create_iam_user()::r.json() returned unknown. ')
                break
            else:
                if r.status_code == self.ecs_authentication_failure:
                    # Attempt to re-authenticate
                    self.authentication.token = None
                    self.authentication.connect()

                    if self.authentication.token is None:
                        self.logger.error('ECSManagementAPI::create_iam_user()::Token Expired.  Unable '
                                          'to re-authenticate to ECS as configured.  Please validate and try again.')
                        raise ECSException("The ECS Data Collection Module was unable to re-authenticate.")
                        break
                else:
                    self.logger.error('ECSManagementAPI::create_iam_user()::/iam?Action=CreateUser '
                                      'call against host ' + self.authentication.host + ' failed with a status code of ' + str(r.status_code))
                    self.response_json = None
                    break
        return self.response_json

    def create_secret_key(self, namespace, object_user):

        while True:
            # Perform ECS Object Namespace API Call
            headers = {'X-SDS-AUTH-TOKEN': "'{0}'".format(self.authentication.token),
                       'content-type': 'application/json', 'Accept': 'application/json'}

            # Build JSON for request
            r = requests.post("{0}//object/user-secret-keys/{1}".format(self.authentication.url, object_user),
                              headers=headers, verify=False,json={'namespace': namespace, 'secretkey': ''})

            if r.status_code == requests.codes.ok:
                self.logger.debug('ECSManagementAPI::create_secret_key()::'
                                  '/object/user-secret-keys/ call returned '
                                  'with a 200 status code.  Text is: ' + r.text)
                self.response_json = r.json()

                self.logger.debug('ECSManagementAPI::create_secret_key()::r.text() contains: \n' + r.text)

                if type(self.response_json) is list:
                    self.logger.debug('ECSManagementAPI::create_secret_key()::r.json() returned a list. ')
                elif type(self.response_json) is dict:
                    self.logger.debug('ECSManagementAPI::create_secret_key()::r.json() returned a dictionary. ')
                else:
                    self.logger.debug('ECSManagementAPI::create_secret_key()::r.json() returned unknown. ')
                break
            else:
                if r.status_code == self.ecs_authentication_failure:
                    # Attempt to re-authenticate
                    self.authentication.token = None
                    self.authentication.connect()

                    if self.authentication.token is None:
                        self.logger.error('ECSManagementAPI::create_secret_key()::Token Expired.  Unable '
                                          'to re-authenticate to ECS as configured.  Please validate and try again.')
                        raise ECSException("The ECS Data Collection Module was unable to re-authenticate.")
                        break
                else:
                    self.logger.error('ECSManagementAPI::create_secret_key()::/object/user-secret-keys/{uid} '
                                      'call against host ' + self.authentication.host + ' failed with a status code of ' + str(r.status_code))
                    self.response_json = None
                    break
        return self.response_json

    def create_iam_secret_key(self, namespace, iam_user):

        while True:
            # Perform ECS IAM Create Secret Key API Call
            headers = {'X-SDS-AUTH-TOKEN': "'{0}'".format(self.authentication.token),
                       'content-type': 'application/json', 'Accept': 'application/json', 'x-emc-namespace': namespace}

            # Create query parameters
            query_parameters = {'UserName': iam_user}

            # Build JSON for request
            r = requests.post("{0}//iam?Action=CreateAccessKey".format(self.authentication.url, iam_user),
                              headers=headers, verify=False, params=query_parameters)

            if r.status_code == requests.codes.ok:
                self.logger.debug('ECSManagementAPI::create_iam_secret_key()::'
                                  '/iam?Action=CreateAccessKey call returned '
                                  'with a 200 status code.  Text is: ' + r.text)
                self.response_json = r.json()

                self.logger.debug('ECSManagementAPI::create_iam_secret_key()::r.text() contains: \n' + r.text)

                if type(self.response_json) is list:
                    self.logger.debug('ECSManagementAPI::create_iam_secret_key()::r.json() returned a list. ')
                elif type(self.response_json) is dict:
                    self.logger.debug('ECSManagementAPI::create_iam_secret_key()::r.json() returned a dictionary. ')
                else:
                    self.logger.debug('ECSManagementAPI::create_iam_secret_key()::r.json() returned unknown. ')
                break
            else:
                if r.status_code == self.ecs_authentication_failure:
                    # Attempt to re-authenticate
                    self.authentication.token = None
                    self.authentication.connect()

                    if self.authentication.token is None:
                        self.logger.error('ECSManagementAPI::create_iam_secret_key()::Token Expired.  Unable '
                                          'to re-authenticate to ECS as configured.  Please validate and try again.')
                        raise ECSException("The ECS Data Collection Module was unable to re-authenticate.")
                        break
                else:
                    self.logger.error('ECSManagementAPI::create_iam_secret_key()::/iam?Action=CreateAccessKey '
                                      'call against host ' + self.authentication.host + ' failed with a status code of ' + str(r.status_code))
                    self.response_json = None
                    break
        return self.response_json

    def create_iam_policy(self, namespace, iam_user, iam_user_type, bucket):

        while True:
            # Perform ECS IAM Create User call
            headers = {'X-SDS-AUTH-TOKEN': "'{0}'".format(self.authentication.token),
                       'content-type': 'application/json', 'Accept': 'application/json', 'x-emc-namespace': namespace}

            # Generate Policy Document based on requested user type
            if iam_user_type == 1:
                iam_policy = '''{"Version": "2012-10-17","Statement": [{"Action": ["s3:GetObject", "s3:GetObjectAcl", "s3:GetObjectLegalHold", "s3:GetObjectRetention", "s3:GetObjectTagging", "s3:GetObjectVersion", "s3:GetObjectVersionAcl", "s3:GetObjectVersionTagging","s3:GetObjectVersionForReplication","s3:GetDetailedReplicationStatus","s3:ListMultipartUploadParts","s3:ListBucketVersions","s3:GetBucketVersioning","s3:GetBucketObjectLockConfiguration","s3:GetBucketAcl","s3:GetBucketCORS","s3:GetLifecycleConfiguration","s3:ListBucketMultipartUploads","s3:GetBucketPolicy","s3:GetReplicationConfiguration","s3:GetBucketNotification","s3:GetBucketMetaDataSearchKey","s3:GetBucketLocation","s3:CreateBucket","s3:DeleteBucket","s3:PutBucketCORS","s3:PutBucketVersioning","s3:PutBucketObjectLockConfiguration","s3:EnableObjectLock","s3:PutLifecycleConfiguration","s3:PutObject","s3:DeleteObject","s3:DeleteObjectVersion","s3:AbortMultipartUpload","s3:PutObjectLegalHold","s3:PutObjectRetention","s3:BypassGovernanceRetention","s3:PutObjectTagging","s3:PutObjectVersionTagging","s3:DeleteObjectTagging","s3:DeleteObjectVersionTagging","s3:PutBucketAcl","s3:PutBucketPolicy","s3:DeleteBucketPolicy","s3:PutObjectAcl","s3:PutObjectVersionAcl","s3:PutReplicationConfiguration","s3:DeleteReplicationConfiguration","s3:ReplicateObject","s3:ReplicateTags","s3:ReplicateDelete","s3:ObjectOwnerOverrideToBucketOwner","s3:PutBucketNotification","s3:ListBucket","s3:ListAllMyBuckets"],"Resource": ["arn:aws:s3:::''' + bucket +  '''/*","arn:aws:s3:::''' + bucket + '''"],"Effect": "Allow","Sid": "VisualEditor0"}]}'''
            else:
                iam_policy = '''{"Version": "2012-10-17","Statement": [{"Sid": "VisualEditor0","Effect": "Allow","Action":["s3:GetObject","s3:GetObjectAcl","s3:GetObjectLegalHold","s3:GetObjectRetention","s3:GetObjectTagging","s3:GetObjectVersion","s3:GetObjectVersionAcl","s3:GetObjectVersionTagging","s3:GetObjectVersionForReplication","s3:GetDetailedReplicationStatus","s3:ListMultipartUploadParts","s3:ListBucketVersions","s3:GetBucketVersioning","s3:GetBucketObjectLockConfiguration","s3:GetBucketAcl","s3:GetBucketCORS","s3:GetLifecycleConfiguration","s3:ListBucketMultipartUploads","s3:GetBucketPolicy","s3:GetReplicationConfiguration","s3:GetBucketNotification","s3:GetBucketMetaDataSearchKey","s3:GetBucketLocation"],"Resource": ["arn:aws:s3:::''' + bucket + '''/*","arn:aws:s3:::''' + bucket + '''"]}]}'''

            test_dumps = json.loads(iam_policy)

            # Create query parameters
            query_parameters = {'Description': "IAM policy for user " + iam_user, 'PolicyName': "baas-" + iam_user, 'PolicyDocument': iam_policy}

            # Build JSON for request
            r = requests.post("{0}//iam?Action=CreatePolicy".format(self.authentication.url),
                              headers=headers, verify=False, params=query_parameters)

            if r.status_code == requests.codes.ok:
                self.logger.debug('ECSManagementAPI::create_iam_policy()::'
                                  '/iam?Action=CreatePolicy call returned '
                                  'with a 200 status code.  Text is: ' + r.text)
                self.response_json = r.json()

                self.logger.debug('ECSManagementAPI::create_iam_policy()::r.text() contains: \n' + r.text)

                if type(self.response_json) is list:
                    self.logger.debug('ECSManagementAPI::create_iam_policy()::r.json() returned a list. ')
                elif type(self.response_json) is dict:
                    self.logger.debug('ECSManagementAPI::create_iam_policy()::r.json() returned a dictionary. ')
                else:
                    self.logger.debug('ECSManagementAPI::create_iam_policy()::r.json() returned unknown. ')
                break
            else:
                if r.status_code == self.ecs_authentication_failure:
                    # Attempt to re-authenticate
                    self.authentication.token = None
                    self.authentication.connect()

                    if self.authentication.token is None:
                        self.logger.error('ECSManagementAPI::create_iam_policy()::Token Expired.  Unable '
                                          'to re-authenticate to ECS as configured.  Please validate and try again.')
                        raise ECSException("The ECS Data Collection Module was unable to re-authenticate.")
                        break
                else:
                    self.logger.error('ECSManagementAPI::create_iam_policy()::/iam?Action=CreatePolicy '
                                      'call against host ' + self.authentication.host + ' failed with a status code of ' + str(r.status_code))
                    self.response_json = None
                    break
        return self.response_json

    def create_bucket(self, namespace, object_user, bucket_name, bucket_quota):

        while True:
            # Perform ECS Object Namespace API Call
            headers = {'X-SDS-AUTH-TOKEN': "'{0}'".format(self.authentication.token),
                       'content-type': 'application/json', 'Accept': 'application/json'}

            # Build JSON for request
            r = requests.post("{0}//object/bucket".format(self.authentication.url),
                             headers=headers, verify=False, json={'namespace': namespace, 'name': bucket_name, 'blockSize': bucket_quota, 'is_stale_allowed': "true",'owner': object_user })

            if r.status_code == requests.codes.ok:
                self.logger.debug('ECSManagementAPI::create_bucket()::'
                                  '/object/bucket call returned '
                                  'with a 200 status code.  Text is: ' + r.text)
                self.response_json = r.json()

                self.logger.debug('ECSManagementAPI::create_bucket()::r.text() contains: \n' + r.text)

                if type(self.response_json) is list:
                    self.logger.debug('ECSManagementAPI::create_bucket()::r.json() returned a list. ')
                elif type(self.response_json) is dict:
                    self.logger.debug('ECSManagementAPI::create_bucket()::r.json() returned a dictionary. ')
                else:
                    self.logger.debug('ECSManagementAPI::create_bucket()::r.json() returned unknown. ')
                break
            else:
                if r.status_code == self.ecs_authentication_failure:
                    # Attempt to re-authenticate
                    self.authentication.token = None
                    self.authentication.connect()

                    if self.authentication.token is None:
                        self.logger.error('ECSManagementAPI::create_bucket()::Token Expired.  Unable '
                                          'to re-authenticate to ECS as configured.  Please validate and try again.')
                        raise ECSException("The ECS Data Collection Module was unable to re-authenticate.")
                        break
                else:
                    self.logger.error('ECSManagementAPI::create_bucket()::/object/bucket '
                                      'call against host ' + self.authentication.host + ' failed with a status code of ' + str(r.status_code))
                    self.response_json = None
                    break
        return self.response_json

    def create_iam_bucket(self, namespace, bucket_name, bucket_quota):

        while True:
            # Perform ECS Object Namespace API Call
            headers = {'X-SDS-AUTH-TOKEN': "'{0}'".format(self.authentication.token),
                       'content-type': 'application/json', 'Accept': 'application/json'}

            iam_root_arn = "urn:ecs:iam::" + namespace + ":root"

            # Build JSON for request
            r = requests.post("{0}//object/bucket".format(self.authentication.url),
                              headers=headers, verify=False, json={'namespace': namespace, 'name': bucket_name, 'blockSize': bucket_quota, 'is_stale_allowed': "true",'owner': iam_root_arn })

            if r.status_code == requests.codes.ok:
                self.logger.debug('ECSManagementAPI::create_bucket()::'
                                  '/object/bucket call returned '
                                  'with a 200 status code.  Text is: ' + r.text)
                self.response_json = r.json()

                self.logger.debug('ECSManagementAPI::create_bucket()::r.text() contains: \n' + r.text)

                if type(self.response_json) is list:
                    self.logger.debug('ECSManagementAPI::create_bucket()::r.json() returned a list. ')
                elif type(self.response_json) is dict:
                    self.logger.debug('ECSManagementAPI::create_bucket()::r.json() returned a dictionary. ')
                else:
                    self.logger.debug('ECSManagementAPI::create_bucket()::r.json() returned unknown. ')
                break
            else:
                if r.status_code == self.ecs_authentication_failure:
                    # Attempt to re-authenticate
                    self.authentication.token = None
                    self.authentication.connect()

                    if self.authentication.token is None:
                        self.logger.error('ECSManagementAPI::create_bucket()::Token Expired.  Unable '
                                          'to re-authenticate to ECS as configured.  Please validate and try again.')
                        raise ECSException("The ECS Data Collection Module was unable to re-authenticate.")
                        break
                else:
                    self.logger.error('ECSManagementAPI::create_bucket()::/object/bucket '
                                      'call against host ' + self.authentication.host + ' failed with a status code of ' + str(r.status_code))
                    self.response_json = None
                    break
        return self.response_json

    def get_bucket_data(self, namespace, bucket):

        while True:
            # Perform ECS Object Namespace API Call
            headers = {'X-SDS-AUTH-TOKEN': "'{0}'".format(self.authentication.token),
                       'content-type': 'application/json', 'Accept': 'application/json'}

            params_dict = {'namespace': namespace, }

            r = requests.get("{0}//object/bucket".format(self.authentication.url),
                             headers=headers, verify=False, params=params_dict)

            if r.status_code == requests.codes.ok:
                self.logger.debug('ECSManagementAPI::get_bucket_data()::'
                                  '/object/bucket call returned '
                                  'with a 200 status code.  Text is: ' + r.text)
                self.response_json = r.json()

                self.logger.debug('ECSManagementAPI::get_bucket_data()::r.text() contains: \n' + r.text)

                if type(self.response_json) is list:
                    self.logger.debug('ECSManagementAPI::get_bucket_data()::r.json() returned a list. ')
                elif type(self.response_json) is dict:
                    self.logger.debug('ECSManagementAPI::get_bucket_data()::r.json() returned a dictionary. ')
                else:
                    self.logger.debug('ECSManagementAPI::get_bucket_data()::r.json() returned unknown. ')
                break
            else:
                if r.status_code == self.ecs_authentication_failure:
                    # Attempt to re-authenticate
                    self.authentication.token = None
                    self.authentication.connect()

                    if self.authentication.token is None:
                        self.logger.error('ECSManagementAPI::get_bucket_data()::Token Expired.  Unable '
                                          'to re-authenticate to ECS as configured.  Please validate and try again.')
                        raise ECSException("The ECS Data Collection Module was unable to re-authenticate.")
                        break
                else:
                    self.logger.error('ECSManagementAPI::get_bucket_data()::/object/bucket '
                                      'call against host ' + self.authentication.host + ' failed with a status code of ' + str(r.status_code))
                    self.response_json = None
                    break
        return self.response_json

    def get_vdc_data(self):

        while True:
            # Perform ECS Object VDC API Call
            headers = {'X-SDS-AUTH-TOKEN': "'{0}'".format(self.authentication.token),
                       'content-type': 'application/json', 'Accept': 'application/json'}

            r = requests.get("{0}//object/vdcs/vdc/local".format(self.authentication.url),
                             headers=headers, verify=False)

            if r.status_code == requests.codes.ok:
                self.logger.debug('ECSManagementAPI::get_vdc_data()::'
                                  '/object/bucket call returned '
                                  'with a 200 status code.  Text is: ' + r.text)
                self.response_json = r.json()

                self.logger.debug('ECSManagementAPI::get_vdc_data()::r.text() contains: \n' + r.text)

                if type(self.response_json) is list:
                    self.logger.debug('ECSManagementAPI::get_vdc_data()::r.json() returned a list. ')
                elif type(self.response_json) is dict:
                    self.logger.debug('ECSManagementAPI::get_vdc_data()::r.json() returned a dictionary. ')
                else:
                    self.logger.debug('ECSManagementAPI::get_vdc_data()::r.json() returned unknown. ')
                break
            else:
                if r.status_code == self.ecs_authentication_failure:
                    # Attempt to re-authenticate
                    self.authentication.token = None
                    self.authentication.connect()

                    if self.authentication.token is None:
                        self.logger.error('ECSManagementAPI::get_vdc_data()::Token Expired.  Unable '
                                          'to re-authenticate to ECS as configured.  Please validate and try again.')
                        raise ECSException("The ECS Data Collection Module was unable to re-authenticate.")
                        break
                else:
                    self.logger.error('ECSManagementAPI::get_vdc_data()::/object/vdcs/vdc/local '
                                      'call against host ' + self.authentication.host + ' failed with a status code of ' + str(r.status_code))
                    self.response_json = None
                    break
        return self.response_json

    def get_ecs_detail_data(self, field, metric_list=[], metric_values={}):
        # Valid 'metric_list' is a list of dictionary items
        # { 't' : '<epoch time>', '<units of measure>' : '<data>' }
        if len(metric_list):
            # Check if this is a valid list of timestamped data points
            # If so, iterate through the list of data points
            if 't' in metric_list[0]:
                for items in metric_list:
                    # Gets the timestamp for this data point
                    epoch_time = items.pop('t')
                    # Get the data point
                    for units in items:
                        data = float(items[units])
                    # Data key'ed to time then field : data
                    if epoch_time in metric_values:
                        metric_values[epoch_time][field] = data
                    else:
                        metric_values[epoch_time] = {}
                        metric_values[epoch_time][field] = data

    def get_ecs_summary_data(self, field, current_epoch, summary_dict={}, summary_values={}):
        # Valid 'summary_dict' is a dictionary of three keys
        # 'Min' and 'Max' which is a list with a single item containing
        # { 't' : '<epoch time>', '<units of measure>' : '<data>' }
        # Third key is 'Avg' which just has a value
        for keys in summary_dict:
            self.logger.debug('ECSManagementAPI::get_ecs_summary_data()::'
                              'Key in summary_dict being processed is: ' + keys)

            if type(summary_dict[keys]) is list:
                # Check non-empty list. Since list is only item we can address
                # the value directly using [0]
                if len(summary_dict[keys]):
                    epoch_time = summary_dict[keys][0].pop('t')
                    for units in summary_dict[keys][0]:
                        data = float(summary_dict[keys][0][units])
                    # Data key'ed to time, then field+keys : data
                    # E.g. field+keys "chunksEcRateSummaryMin"
                    if epoch_time in summary_values:
                        summary_values[epoch_time][field+keys] = data
                    else:
                        summary_values[epoch_time] = {}
                        summary_values[epoch_time][field+keys] = data
            # "Avg" value which is just key : value
            else:
                if current_epoch in summary_values:
                    summary_values[current_epoch][field+keys] = \
                        float(summary_dict[keys])
                else:
                    summary_values[current_epoch] = {}
                    summary_values[current_epoch][field+keys] = \
                        float(summary_dict[keys])


class ECSUtility(object):
    """
    ECS Utility Class
    """

    def __init__(self, authentication, logger, vdc_lookup_file):
        self.authentication = authentication
        self.logger = logger
        self.vdc_lookup = vdc_lookup_file
        self.vdc_json = None

        if vdc_lookup_file is None:
            raise ECSException("No file path to the ECS VDC Lookup configuration provided.")

        if not os.path.exists(vdc_lookup_file):
            raise ECSException("The ECS VDC Lookup configuration file path does not exist: " + vdc_lookup_file)

        # Attempt to open configuration file
        try:
            with open(vdc_lookup_file, 'r') as f:
                self.vdc_json = json.load(f)
        except Exception as e:
            raise ECSException("The following unexpected exception occurred in the "
                               "ECS Data Collection Module attempting to parse "
                               "the ECS VDC Lookup configuration file: " + e.message)
