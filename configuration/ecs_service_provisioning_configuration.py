"""
DELL Object Service Provisioning
"""
import logging
import os
import json

# Constants
MODULE_NAME = "ecs-service_provisioning_configuration"        # Module Name
BASE_CONFIG = 'BASE'                                          # Base Configuration Section
ECS_CONNECTION_CONFIG = 'ECS_CONNECTION'                      # ECS Connection Configuration Section
DATABASE_CONNECTION_CONFIG = 'SQLLITE_DATABASE_CONNECTION'    # SQLLite Database Connection Configuration Section
ECS_API_POLLING_INTERVALS = 'ECS_API_POLLING_INTERVALS'       # ECS API Call Interval Configuration Section
SMTP_CONNECTION_CONFIG = 'SMTP'                               # SMTP Configuration Section
SLACK_CONFIG = 'SLACK'                                        # Slack Configuration Section


class InvalidConfigurationException(Exception):
    pass


class ECSSmtpAlertConfiguration(object):
    def __init__(self, config, tempdir):

        if config is None:
            raise InvalidConfigurationException("No file path to the ECS Service Provisioning Module configuration provided")

        if not os.path.exists(config):
            raise InvalidConfigurationException("The ECS Service Provisioning Module configuration "
                                                "file path does not exist: " + config)
        if tempdir is None:
            raise InvalidConfigurationException("No path for temporary file storage provided")

        # Store temp file storage path to the configuration object
        self.tempfilepath = tempdir

        # Attempt to open configuration file
        try:
            with open(config, 'r') as f:
                parser = json.load(f)
        except Exception as e:
            raise InvalidConfigurationException("The following unexpected exception occurred in the "
                                                "ECS Service Provisioning Module attempting to parse "
                                                "the configuration file: " + e.message)

        # We parsed the configuration file now lets grab values
        self.ecsconnections = parser[ECS_CONNECTION_CONFIG]

        # Set logging level
        logging_level_raw = parser[BASE_CONFIG]['logging_level']
        self.logging_level = logging.getLevelName(logging_level_raw.upper())

        # Retrieve email deliver system (We support SMTP or SendGrid
        self.alert_delivery = parser[BASE_CONFIG]['alert_delivery']

        # Validate email delivery system
        if self.alert_delivery not in ['smtp', 'slack']:
            raise InvalidConfigurationException(
                "Alert delivery system must be set to either smtp, sendgrid, or slack.")

        # Grab SQL Lite database settings:
        self.database_name = parser[DATABASE_CONNECTION_CONFIG]['databasename']

        # Grab ECS API Polling Intervals
        self.modules_intervals = parser[ECS_API_POLLING_INTERVALS]

        # Validate logging level
        if logging_level_raw not in ['debug', 'info', 'warning', 'error']:
            raise InvalidConfigurationException(
                "Logging level can be only one of ['debug', 'info', 'warning', 'error']")

        # Iterate through ECS API Module Interval Configuration and make sure intervals are numeric greater than 0
        for i, j in self.modules_intervals.items():
            if not j.isnumeric():
                raise InvalidConfigurationException("The ECS API Polling Interval of " + j + " for API Call " + i +
                                                    " is not numeric.")

        # Iterate through all configured ECS connections and validate connection info
        for ecsconnection in self.ecsconnections:
            # Validate ECS Connections values
            if not ecsconnection['protocol']:
                raise InvalidConfigurationException("The ECS Management protocol is not "
                                                    "configured in the module configuration")
            if not ecsconnection['host']:
                raise InvalidConfigurationException("The ECS Management Host is "
                                                    "not configured in the module configuration")
            if not ecsconnection['port']:
                raise InvalidConfigurationException("The ECS Management port is "
                                                    "not configured in the module configuration")
            if not ecsconnection['user']:
                raise InvalidConfigurationException("The ECS Management User is "
                                                    "not configured in the module configuration")
            if not ecsconnection['password']:
                raise InvalidConfigurationException("The ECS Management Users password is not configured "
                                                    "in the module configuration")
            if not ecsconnection['default_replication_group_id']:
                raise InvalidConfigurationException("The ECS Management default replication group id is not configured "
                                                "in the module configuration")

        # SMTP Settings
        self.smtp_host = parser[SMTP_CONNECTION_CONFIG]['host']
        self.smtp_port = parser[SMTP_CONNECTION_CONFIG]['port']
        self.smtp_user = parser[SMTP_CONNECTION_CONFIG]['user']
        self.smtp_password = parser[SMTP_CONNECTION_CONFIG]['password']
        self.smtp_authentication_required = parser[SMTP_CONNECTION_CONFIG]['authenticationrequired']
        self.smtp_fromemail = parser[SMTP_CONNECTION_CONFIG]['fromemail']
        self.smtp_toemail = parser[SMTP_CONNECTION_CONFIG]['toemail']
        self.smtp_alert_polling_interval = parser[SMTP_CONNECTION_CONFIG]['polling_interval_seconds']

        # If the email delivery system is SMTP and authentication required is set then make
        # sure we have a user and password we can use
        if self.alert_delivery == 'smtp':
            if self.smtp_authentication_required == '1':
                if not self.smtp_user or not self.smtp_password:
                    raise InvalidConfigurationException("The SMTP Authentication Required "
                                                        "is set but the user or password is not set.")

        # Slack Settings
        self.slack_environment_variable_for_webhook_url = \
            parser[SLACK_CONFIG]['slack_environment_variable_for_webhook_url']

        # If Slack is the alert delivery method then make sure that the proper environment variable is set
        if self.alert_delivery == 'slack':
            if self.slack_environment_variable_for_webhook_url:
                # We have a value set for the Slack Webhook URL Environment Variable now lets see if it actually exists
                if self.slack_environment_variable_for_webhook_url in os.environ:
                    self.slack_webhook = os.environ.get(self.slack_environment_variable_for_webhook_url)
                else:
                    raise InvalidConfigurationException("Slack is a configured alert delivery mechanism "
                                                        "but the configured environment variable value for the "
                                                        "Web Hook is not set.")
            else:
                raise InvalidConfigurationException("Slack is a configured alert delivery mechanism "
                                                    "but the environment variable value for the "
                                                    "Web Hook is not set in the configuration.")

        self.slack_alert_polling_interval = parser[SLACK_CONFIG]['polling_interval_seconds']

