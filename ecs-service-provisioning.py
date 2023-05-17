"""
DELL Object Service Provisioning
"""

from configuration.ecs_service_provisioning_configuration import ECSSmtpAlertConfiguration
from ecslogger import ecslogger
from ecsdatacollection.ecsdatacolletion import ECSAuthentication
from ecsdatacollection.ecsdatacolletion import ECSManagementAPI
from ecsdatacollection.ecsdatacolletion import ECSUtility
from ecssqllite.ecssqllite import SQLLiteUtility
from ecssmtp.ecssmtp import ECSSMTPUtility
from ecsslack.ecsslack import ECSSlackUtility
import sqlite3
import argparse
import datetime
import os
import traceback
import signal
import time
import logging
import threading
import json
import xml.etree.ElementTree as ET


# Constants
MODULE_NAME = "ecs-service-provisioning"                    # Module Name
INTERVAL = 30                                               # In seconds
CONFIG_FILE = 'ecs_service_provisioning_configuration.json' # Default Configuration File
VDC_LOOKUP_FILE = 'ecs_vdc_lookup.json'                     # VDC ID Lookup File
TOOL_VERSION = "1.0.00"                                     # Tool Version

# Globals
_configuration = None
_ecsManagementNode = None
_ecsManagementUser = None
_ecsManagementUserPassword = None
_logger = None
_ecsAuthentication = list()
_sqlLiteClient = None
_ecsVDCLookup = None
_ecsManagementAPI = {}
_smtpClient = None
_smtpUtility = None
_slackUtility = None

"""
Class to listen for signal termination for controlled shutdown
"""


class ECSDataCollectionShutdown:

    kill_now = False

    def __init__(self):
        signal.signal(signal.SIGINT, self.controlled_shutdown)
        signal.signal(signal.SIGTERM, self.controlled_shutdown)

    def controlled_shutdown(self):
        self.kill_now = True


class ECSDataCollection (threading.Thread):
    def __init__(self, method, sqlclient, logger, ecsmanagmentapi, pollinginterval, tempdir):
        threading.Thread.__init__(self)
        self.method = method
        self.sqlclient = sqlclient
        self.logger = logger
        self.ecsmanagmentapi = ecsmanagmentapi
        self.pollinginterval = pollinginterval
        self.tempdir = tempdir

        logger.info(MODULE_NAME + '::ECSDataCollection()::init method of class called')

    def run(self):
        try:
            self.logger.info(MODULE_NAME + '::ECSDataCollection()::Starting thread with method: ' + self.method)

            if self.method == 'process_service_requests()':
                process_service_requests(self.logger, self.ecsmanagmentapi, self.pollinginterval, self.tempdir, self.sqlclient)
            else:
                self.logger.info(MODULE_NAME + '::ECSDataCollection()::Requested method '
                                 + self.method + ' is not supported.')
        except Exception as e:
            _logger.error(MODULE_NAME + 'ECSDataCollection::run()::The following unexpected '
                                        'exception occurred: ' + str(e) + "\n" + traceback.format_exc())


class ECSServiceRequestProcessingEmails (threading.Thread):
    def __init__(self, method, logger, configuration, smtputility, slackutility):
        threading.Thread.__init__(self)
        self.method = method
        self.logger = logger
        self.configuration = configuration
        self.smtpUtility = smtputility
        self.slackUtility = slackutility

        logger.info(MODULE_NAME + '::ECSServiceRequestProcessingEmails()::init method of class called')

    def run(self):
        try:
            self.logger.info(MODULE_NAME + '::ECSServiceRequestProcessingEmails()::Starting thread with method: ' + self.method)

            if self.method == 'send_processed_service_request_notifications()':
                send_processed_service_request_notifications(self.logger, self.configuration, self.smtpUtility, self.slackUtility)
            else:
                self.logger.info(MODULE_NAME + '::ECSServiceRequestProcessingEmails()::Requested method '
                                 + self.method + ' is not supported.')
        except Exception as e:
            _logger.error(MODULE_NAME + 'ECSServiceRequestProcessingEmails::run()::The following unexpected '
                                        'exception occurred: ' + str(e) + "\n" + traceback.format_exc())


def ecs_config(config, vdc_config, temp_dir):
    global _configuration
    global _logger
    global _ecsAuthentication
    global _ecsVDCLookup

    try:
        # Load and validate module configuration
        _configuration = ECSSmtpAlertConfiguration(config, temp_dir)

        # Grab loggers and log status
        _logger = ecslogger.get_logger(__name__, _configuration.logging_level)
        _logger.info(MODULE_NAME + '::ecs_config()::We have configured logging level to: '
                     + logging.getLevelName(str(_configuration.logging_level)))
        _logger.info(MODULE_NAME + '::ecs_config()::Configuring ECS Data Collection Module complete.')
    except Exception as e:
        _logger.error(MODULE_NAME + '::ecs_config()::The following unexpected '
                                    'exception occured: ' + str(e) + "\n" + traceback.format_exc())


def ecs_authenticate():
    global _ecsAuthentication
    global _configuration
    global _logger
    global _ecsManagementAPI
    connected = True

    try:
        # Wait till configuration is set
        while not _configuration:
            time.sleep(1)

        # Iterate over all ECS Connections configured and attempt tp Authenticate to ECS
        for ecsconnection in _configuration.ecsconnections:

            # Attempt to authenticate
            auth = ECSAuthentication(ecsconnection['protocol'], ecsconnection['host'], ecsconnection['user'],
                                     ecsconnection['password'], ecsconnection['port'], _logger)
            auth.connect()

            # Check to see if we have a token returned
            if auth.token is None:
                _logger.error(MODULE_NAME + '::ecs_init()::Unable to authenticate to ECS '
                                            'as configured.  Please validate and try again.')
                connected = False
                break
            else:
                _ecsAuthentication.append(auth)

                # Instantiate ECS Management API object, and it to our list, and validate that we are authenticated
                _ecsManagementAPI[ecsconnection['host']] = ECSManagementAPI(auth, _logger)
                if not _ecsAuthentication:
                    _logger.info(MODULE_NAME + '::ecs_authenticate()::ECS Data Collection '
                                               'Module is not ready.  Please check logs.')
                    connected = False
                    break

        return connected

    except Exception as e:
        _logger.error(MODULE_NAME + '::ecs_authenticate()::Cannot authenticate to ECS. Cause: '
                      + str(e) + "\n" + traceback.format_exc())
        connected = False
        return connected


def sqllite_init():
    global _sqlLiteClient
    global _configuration
    global _logger
    connected = True

    try:
        # Wait till configuration is set
        while not _configuration:
            time.sleep(1)

        # Instantiate utility object and check to see if our database exists
        db_utility = SQLLiteUtility(_configuration, _logger)
        sql_database = db_utility.open_sqllite_db(_configuration.database_name)

        # If database is not found then connect with no database, create the database, and then switch to it
        if sql_database is None:
            _logger.error(MODULE_NAME + '::sqllite_init()::Unable to open/create SQLLite database as configured.  '
                                        'Please validate and try again.')
            connected = False
        else:
            _logger.info(MODULE_NAME + '::sqllite_init()::Successfully connected to SQLLite as configured.')
            _sqlLiteClient = sql_database

            # Let's check if table exits
            ecsservicerequest = """ CREATE TABLE IF NOT EXISTS ecsservicerequests (
                                        id integer PRIMARY KEY,
                                        userFirstName text NOT NULL,
                                        userLastName text NOT NULL,
                                        userEmail text NOT NULL,
                                        adminUser int NOT NULL,
                                        requestedNamespace text NOT NULL,
                                        requestedNameQuota int NOT NULL,
                                        requestedBucketName text NOT NULL,
                                        requestedBucketQuota int NOT NULL,
                                        dateRequestCreated date,
                                        dateRequestFullfilled date,
                                        dateRequestorEmailed date,
                                        status text NOT NULL
                                    ); """
            dbcur = sql_database.cursor()
            dbcur.execute(ecsservicerequest)

            # Add a default test record
            service_request_create_date = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
            service_request_id = 1
            service_request_first_name = "Steve"
            service_request_last_name = "Beckwith"
            service_request_email = "steve.beckwith@dell.com"
            service_request_admin_user = 0
            service_request_namespace = "acme-seb"
            service_request_namespace_quota = 20000
            service_request_bucket = "test-provision-bucket01"
            service_request_bucket_quota = 1000
            service_request_status = "U"
            service_request_data = (service_request_id, service_request_first_name, service_request_last_name, service_request_email, service_request_admin_user, service_request_namespace, service_request_namespace_quota,service_request_bucket, service_request_bucket_quota,service_request_create_date, '', '', service_request_status)

            # Create SQL Insert Statement and execute
            # sql = ''' INSERT INTO ecsservicerequests(id,userFirstName,userLastName,userEmail,adminUser,requestedNamespace,requestedNameQuota,requestedBucketName,requestedBucketQuota,dateRequestCreated,dateRequestFullfilled,dateRequestorEmailed,status) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) '''
            # dbcur.execute(sql, service_request_data)
            # sql_database.commit()

            dbcur.close()

        return connected

    except Exception as e:
        _logger.error(MODULE_NAME + '::sqllite_init()::Cannot initialize SQL Lite database. Cause: '
                      + str(e) + "\n" + traceback.format_exc())
        connected = False
        return connected


def process_service_requests(logger, ecsmanagmentapi, pollinginterval, tempdir, sqlclient):

    try:
        ecsconnection = list(ecsmanagmentapi.items())[0][1]
        configuration_details = _configuration.ecsconnections[0]

        # Start polling loop
        while True:
            try:
                # Create a connection to the database
                db_utility = SQLLiteUtility(_configuration, _logger)
                sql_database = db_utility.open_sqllite_db(_configuration.database_name)

                # Reset new requests counter
                row_count = 0

                _logger.info(MODULE_NAME + '::process_service_requests::About to select all unprocessed services requests in the database.')

                unprocessed_service_requests = """ SELECT * FROM ecsservicerequests where status = 'U'; """

                # Setup cursor and execute SQL statement
                database_cursor = sql_database.cursor()
                database_cursor.execute(unprocessed_service_requests)

                # Process query results into a list of dictionary's
                r = [dict((database_cursor.description[i][0], value)
                          for i, value in enumerate(row)) for row in database_cursor.fetchall()]

                # If we don't have any unprocessed entries then break out and wait for the next cycle
                if r is None:
                    unprocessed_service_requests = 0
                    _logger.info(MODULE_NAME + '::process_service_requests::Discovered ' + str(unprocessed_service_requests) + ' new service requests.')
                    break
                else:
                    unprocessed_service_requests = len(r)
                    _logger.info(MODULE_NAME + '::process_service_requests::Discovered ' + str(unprocessed_service_requests) + ' new service requests.')

                # Lets iterate over service requests
                for service_request in r:
                    # Extract service request details

                    service_request_id = service_request['id']
                    user_first_name = service_request['userFirstName']
                    user_last_name = service_request['userLastName']
                    user_email = service_request['userEmail']
                    user_is_admin = service_request['adminUser']
                    requested_namespace = service_request['requestedNamespace']
                    requested_namespace_quota = service_request['requestedNameQuota']
                    requested_bucket_name = service_request['requestedBucketName']
                    requested_bucket_quota = service_request['requestedBucketQuota']
                    data_request_created = service_request['dateRequestCreated']

                    # Check if namespace exists
                    namespace_data = ecsconnection.get_namespace_details(requested_namespace)

                    if namespace_data is None:
                        # Namespace doesn't exist so let's create a namespace admin user and then the namespace
                        namespace_admin_user_data = ecsconnection.create_namespace_admin(requested_namespace + "-admin")

                        # Create the namespace if we created the namespace admin user
                        if namespace_admin_user_data is not None:
                            namespace_data = ecsconnection.create_namespace(requested_namespace, requested_namespace + "-admin", configuration_details["default_replication_group_id"])

                            # If we successfully created the namespace then go ahead a set the namespace quota
                            if namespace_data is not None:

                                # if requested_namespace_quota > 0:
                                #     bucket_quota_data = ecsconnection.update_namespace_quota(requested_namespace, requested_namespace_quota)
                                # else:
                                bucket_quota_data = "1"

                                if bucket_quota_data is not None:
                                    # Create the bucket
                                    bucket_data = ecsconnection.create_iam_bucket(requested_namespace, requested_bucket_name, requested_bucket_quota)

                                    # If we succesfully created the bucket then lets generate a custom IAM policy for the user and bucket
                                    if bucket_data is not None:

                                        # Create a corresponding IAM policy based on the type of user were provisioning
                                        policy_data = ecsconnection.create_iam_policy(requested_namespace, requested_namespace + "-iam", user_is_admin, requested_bucket_name)

                                        # If we created the policy then go
                                        if policy_data is not None:
                                            policy_arn = policy_data["CreatePolicyResult"]["Policy"]["Arn"]
                                            policy_name = policy_data["CreatePolicyResult"]["Policy"]["PolicyName"]

                                            iam_user_data = ecsconnection.create_iam_user(requested_namespace, requested_namespace + "-iam", policy_arn)
                                            iam_user_name = iam_user_data["CreateUserResult"]["User"]["UserName"]

                                            if iam_user_data is not None:
                                                secret_key_data = ecsconnection.create_iam_secret_key(requested_namespace, requested_namespace + "-iam")
                                                secret_key_access_key = secret_key_data["CreateAccessKeyResult"]["AccessKey"]["AccessKeyId"]
                                                secret_key_secret = secret_key_data["CreateAccessKeyResult"]["AccessKey"]["SecretAccessKey"]

                                                if secret_key_data is not None:

                                                    # We've completed processing the service request now update the request as processed
                                                    logger.info(MODULE_NAME + '::process_service_requests()::Service request id processed.  The following provisioning took place:')
                                                    logger.info(MODULE_NAME + '::process_service_requests()::\t\tService Request ID: ' + str(service_request_id))
                                                    logger.info(MODULE_NAME + '::process_service_requests()::\t\tNamespace Admin User ' + requested_namespace + '-iam Created.')
                                                    logger.info(MODULE_NAME + '::process_service_requests()::\t\tNamespace ' + requested_namespace + ' created.')
                                                    logger.info(MODULE_NAME + '::process_service_requests()::\t\tBucket ' + requested_bucket_name + ' with quota ' + str(requested_bucket_quota) + ' created.')
                                                    logger.info(MODULE_NAME + '::process_service_requests()::\t\tIAM Policy ' + policy_name + ' created.')
                                                    logger.info(MODULE_NAME + '::process_service_requests()::\t\tIAM User ' + iam_user_name + ' created.')
                                                    logger.info(MODULE_NAME + '::process_service_requests()::\t\tAccess Key ID ' + secret_key_access_key + ' for IAM User ' + iam_user_name + ' created.')
                                                    logger.info(MODULE_NAME + '::process_service_requests()::\t\tSecret Key ID ' + secret_key_secret + ' for IAM User ' + iam_user_name + ' created.')
                                                    service_request_completed_date = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
                                                    service_request_update = """ UPDATE ecsservicerequests SET status = ?, dateRequestFullfilled = ? WHERE id = ?; """
                                                    database_cursor.execute(service_request_update, ('P', service_request_completed_date, service_request_id,))
                                                    sql_database.commit()

                    # Close the database as needed
                    database_cursor.connection.close()

            except Exception as ex:
                logger.error(MODULE_NAME + '::process_service_requests()::The following unexpected '
                                           'exception occurred: ' + str(ex) + "\n" + traceback.format_exc())

            if controlledShutdown.kill_now:
                logger.info(MODULE_NAME + '::process_service_requests()::Shutdown detected.  Terminating polling.')
                break

            # Wait for specific polling interval
            time.sleep(float(pollinginterval))

    except Exception as e:
        _logger.error(MODULE_NAME + '::process_service_requests()::The following unexpected '
                                    'exception occurred: ' + str(e) + "\n" + traceback.format_exc())


def list_requests_table(sqllite_db):
    global _logger
    """
    Query the current contents of the service requests database and provide it in JSON
    """
    try:
        rowcount = 0

        _logger.info(MODULE_NAME + '::list_requests_table::About to list all services requests in the database.')
        """
        Select all records in the service request table 
        """
        service_requests_select = """ SELECT * FROM ecsservicerequests; """

        cur = sqllite_db.cursor()
        cur.execute(service_requests_select)
        r = [dict((cur.description[i][0], value) \
                  for i, value in enumerate(row)) for row in cur.fetchall()]
        cur.connection.close()
        return r if r else None

    except Exception as e:
        _logger.error(MODULE_NAME + '::list_requests_table()::The following '
                                    'unhandled exception occurred: ' + e.message)
        return None


def clear_request_table(sqllite_db):
    """
    Clear the current contents of the service requests database table
    """
    try:
        _logger.info(MODULE_NAME + '::clear_request_table::About to clear all extracted alerts in the database.')

        # Delete all records in the extracted alerts table
        service_requests_delete = """ DELETE FROM ecsservicerequests; """

        cur = sqllite_db.cursor()
        cur.execute(service_requests_delete)
        sqllite_db.commit()
        cur.connection.close()
        return True

    except Exception as e:
        _logger.error(MODULE_NAME + '::clear_request_table()::The following '
                                    'unhandled exception occurred: ' + e.message)
        return False


def send_processed_service_request_notifications(logger, configuation, smtputility, slackutility):

    # Locals
    global _ecsManagementAPI

    try:
        rowcount = 0

        # Retrieve polling interval based on email system being used
        if configuation.alert_delivery == 'smtp':
            # SMTP email delivery is configured
            interval = configuation.smtp_alert_polling_interval
        else:
            # Slack message deliver
            interval = configuation.slack_alert_polling_interval

        # Start polling loop
        while True:
            try:
                _logger.info(MODULE_NAME + '::ecs_send_email_alerts::About to poll for extracted alerts in '
                                           'the database that have not been emailed.')

                # reset sent email counter
                sent_emails = 0

                # Create a connection to the database
                db_utility = SQLLiteUtility(configuation, logger)
                sql_database = db_utility.open_sqllite_db(configuation.database_name)

                # Select records in the extracted alerts table with the
                ecsalertsselect = """ SELECT * FROM ecsalerts WHERE emailAlerted = 0; """

                sql_database.row_factory = sqlite3.Row
                cur = sql_database.cursor()
                cur.execute(ecsalertsselect)
                rows = cur.fetchall()

                # Process any returned row but sending the email and updating the sent flag.
                for row in rows:
                    if row is None:
                        break

                    # Format and send an email
                    rowcount += 1

                    # Send email based on configured email delivery system
                    if configuation.alert_delivery == 'smtp':
                        # SMTP email delivery is configured
                        smtputility.smtp_send_email(row)
                    else:
                        slackutility.slack_send_message(row)

                    # Update notification alert sent state on row
                    current_time = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
                    row_id = row[0]
                    alert_id = row[3]
                    managementIp = row[2]
                    ecsalertupdate = """ UPDATE ecsalerts SET emailAlerted = 1, dateEmailed = ? WHERE id = ?; """
                    cur.execute(ecsalertupdate, (current_time, row_id,))
                    sql_database.commit()

                    # Increment sent email count
                    sent_emails += 1

                    # If we are acknowledging alerts after notification make the API call
                    if str(configuation.acknowledge_alerts).upper() == 'YES':
                        _ecsManagementAPI[managementIp].ecs_acknowledge_alert(alert_id)

                        # Update alert acknowledge date
                        current_time2 = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
                        row_id = row[0]
                        ecsalertupdate2 = """ UPDATE ecsalerts SET alertCleared = 1, dateCleared = ? WHERE id = ?; """
                        cur.execute(ecsalertupdate2, (current_time2, row_id,))
                        sql_database.commit()

                # Close the database connection when we have processed all eligible records
                sql_database.close()

                _logger.info(MODULE_NAME + '::ecs_send_email_alerts::Processed ' + str(sent_emails) +
                             ' new alerts and sent notifications.')

            except Exception as e:
                _logger.error(MODULE_NAME + '::ecs_send_email_alerts()::The following '
                                            'unhandled exception occurred: ' + e.message)

            if controlledShutdown.kill_now:
                logger.info(MODULE_NAME + '::ecs_send_email_alerts()::Shutdown detected.  Terminating polling.')
                break

            # Wait for specific polling interval
            time.sleep(float(interval))

    except Exception as e:
        _logger.error(MODULE_NAME + '::ecs_send_email_alerts()::The following unexpected '
                                    'exception occurred: ' + str(e) + "\n" + traceback.format_exc())


def ecs_data_collection():
    global _ecsAuthentication
    global _logger
    global _ecsManagementAPI
    global _sqlLiteClient
    global _smtpClient

    try:
        # Wait till configuration is set
        while not _configuration:
            time.sleep(1)

        # Now lets spin up a thread for each API call with its own custom polling interval by iterating
        # through our module configuration
        for i, j in _configuration.modules_intervals.items():
            method = str(i)
            interval = str(j)
            t = ECSDataCollection(method, _sqlLiteClient, _logger, _ecsManagementAPI, interval,
                                  _configuration.tempfilepath)
            t.start()

        # Finally, spin up a thread to monitor the service requests table for requests that been processed but
        # not sent via SMTP
        #t2 = ECSServiceRequestProcessingEmails('send_processed_service_request_notifications()', _logger, _configuration, _smtpUtility, _slackUtility)
        #t2.start()

    except Exception as e:
        _logger.error(MODULE_NAME + '::ecs_data_collection()::A failure occurred during data collection. Cause: '
                      + str(e) + "\n" + traceback.format_exc())


"""
Main 
"""
if __name__ == "__main__":

    try:
        # Command line argument processing
        helpdetail = 'ecs-service-provisioning demonstrates the provisioning of  ' \
                     'object storage for a service provider model using the ECS Management API.'
        parser = argparse.ArgumentParser(description=helpdetail)

        parser.add_argument("-c", "--clear", help="Clear the service provisioning request database table.", action="store_true")
        parser.add_argument("-e", "--extracted", help="List all service provisioning request database records.", action="store_true")
        # parser.add_argument("-s", "--sent", help="List records in the extracted "
        #                                          "alerts database table that have been emailed.", action="store_true")
        # parser.add_argument("-u", "--unsent", help="List records in the extracted "
        #                                            "alerts database table that have NOT "
        #                                            "been emailed.", action="store_true")

        args = parser.parse_args()

        # Dump out application path and setup application directories
        currentApplicationDirectory = os.getcwd()
        configFilePath = os.path.abspath(os.path.join(currentApplicationDirectory, "configuration", CONFIG_FILE))
        vdcLookupFilePath = os.path.abspath(os.path.join(currentApplicationDirectory, "configuration", VDC_LOOKUP_FILE))
        tempFilePath = os.path.abspath(os.path.join(currentApplicationDirectory, "temp"))

        # Create temp directory if it doesn't already exist
        if not os.path.isdir(tempFilePath):
            os.mkdir(tempFilePath)
        else:
            # The directory exists so lets scrub any temp XML files out that may be in there
            files = os.listdir(tempFilePath)
            for file in files:
                if file.endswith(".xml"):
                    os.remove(os.path.join(currentApplicationDirectory, "temp", file))

        # Initialize configuration object
        ecs_config(configFilePath, vdcLookupFilePath, tempFilePath)

        # Wait till we have a valid configuration object
        while not _configuration:
            time.sleep(1)

        _logger.info(MODULE_NAME + '::ecs_service_provisioning:main()::Configuration initialization complete.')
        _logger.info(MODULE_NAME + '::ecs_service_provisioning:main()::Current directory is : ' + currentApplicationDirectory)
        _logger.info(MODULE_NAME + '::ecs_service_provisioning:main()::Configuration file path is : ' + configFilePath)

        # Initialize the database
        if sqllite_init():

            # Process command line arguments
            if args.extracted:
                alertsJson = list_requests_table(_sqlLiteClient)
                if alertsJson:
                    print(json.dumps(alertsJson, indent=4, separators=(',', ': '), sort_keys=True))
                else:
                    _logger.error(MODULE_NAME + '::ecs_service_provisioning::Returned 0 extracted alerts from the .')
            else:
                if args.clear:
                    print('ECS Object Service Provisioning')
                    # Let's make sure they really want to clear that table
                    data = input("Your about to clear all records in the "
                                 "service requests database table.  Are you sure?")

                    if data.capitalize() == 'YES':
                        clear_request_table(_sqlLiteClient)
                else:
                    continue_processing = False

                    # Now let's initialize the alert delivery system
                    if _configuration.alert_delivery == 'smtp':
                        _smtpUtility = ECSSMTPUtility(_configuration, _logger)
                        continue_processing = _smtpUtility.check_smtp_server_connection()
                    else:
                        _slackUtility = ECSSlackUtility(_configuration, _logger)
                        continue_processing = True

                    # If we were able to initialize our email delivery system then continue
                    if continue_processing:
                        # Perform normal alert monitoring processing

                        # Close SqlLite connection object so the data
                        # collection threads can each create their own
                        _sqlLiteClient.close()

                        # Create object to support controlled shutdown
                        controlledShutdown = ECSDataCollectionShutdown()

                        # Initialize connection to ECS(s)
                        if ecs_authenticate():

                            # Launch ECS Data Collection polling threads
                            ecs_data_collection()

                            # Check for shutdown
                            if controlledShutdown.kill_now:
                                print(MODULE_NAME + "__main__::Controlled shutdown completed.")

    except Exception as e:
        print(MODULE_NAME + '__main__::The following unexpected error occurred: '
              + str(e) + "\n" + traceback.format_exc())

