# ecs-email-alerting configuration
----------------------------------------------------------------------------------------------
ecs-email-alerting is a PYTHON based script that monitors for alerts from DELL EMC's 
Elastic Cloud Storage (ECS) Product and sends emails via SMTP with alert information

ecs-email-alerting utilizes the ECS Managment REST API's to gather alert data from ECS which is 
then stored locally for subsequent SMTP email processing.

We've provided two sample configuration files:

NOTE: These files are in JSON format so make sure you understand JSON syntax.

- ecs_email_alert_configuration.sample: Change file suffix from .sample to .json and configure as needed
  This contains the tool configuration for one ore more ECS clusters to monitor, a local SQL Lite database to store extracted 
  alerts, either SMTP or SendGrid info for email delivery, logging level, etc. 
  
  Here is the sample configuration:
  
  BASE:
  logging_level - The default is "info" but it can be set to "debug" to generate a LOT of details
  data store - At the moment it's set to "sqllite" but could be enhanced to support other datastores
  email_delivery - This is the email delivery system to use.  This can be either "smtp" or "sendgrid"
  
  ECS_CONNECTION:
  protocol - Should be set to "https"
  host - This is the IP address of FQDN of an ECS node
  port - This is always "4443" which is the ECS Management API port
  user - This is the user id of an ECS Management User 
  password - This is the password for the ECS Management User
  default_replication_group_id - urn of replication group that should be used to create namespaces
  
  SQLLITE_DATABASE_CONNECTION:
  databasename = This is name of the SQLLite database that will be created and used for processing
  
  ECS_API_POLLING_INTERVALS
  This is a dictionary that contains the names of the ECSManagementAPI class methods that are used to perform 
  data extraction along with a numeric value that defines the polling interval in seconds to be used to call the method.
  
  "ecs_collect_alert_data()": "120", 
  
  Currently this application only supports 1 method in ECSManagementAPI class.  
  
  SMTP
    host = This is the IP address or FQDN of the SMTP server
    port - This is the port that the SMTP server is listening on.  Default is "25"
    user - This is the user id of the SMTP user to use to authenticate to the SMTP server if required
    password - This is the password of the SMTP user to authenticate to the SMTP server if required
    authenticationrequired = This value determines if the SMTP server requires authentication. 
    fromemail - The email address that should be used as the from email when sending emails
    toemail - This is a comma seperated list of email addresses that emails should be sent to
    polling_interval_seconds - This determines how often the applicaiton will look for newly extracted alerts that need to be emailed

  SEND_GRID
    api_key = This is the SendGrid API Key to use to send emails
    fromemail - The email address that should be used as the from email when sending emails
    toemail - This is a comma seperated list of email addresses that emails should be sent to
    polling_interval_seconds - This determines how often the applicaiton will look for newly extracted alerts that need to be emailed


