"""
DELL EMC ECS SMTP Email Module.
"""


import smtplib
import time
import email.message

# Constants
MODULE_NAME = "ecssmtp"                  # Module Name

class ECSSMTPException(Exception):
    pass


class ECSSMTPUtility(object):
    """
    Stores ECS SMTP Email Functions
    """
    def __init__(self, config, logger):
        self.config = config
        self.logger = logger

    def check_smtp_server_connection(self):
        """
        Checks if a database exists and create if it doesn't
        """
        try:
            connected = True

            while not self.config:
                time.sleep(1)

            # Create SMTP server and handshake
            server = smtplib.SMTP(self.config.smtp_host + ':' + self.config.smtp_port)
            server.connect(self.config.smtp_host + ':' + self.config.smtp_port)

            self.logger.info(MODULE_NAME + '::check_smtp_server_connection::Successfully '
                                           'connected to the configured SMTP server and port at: ' + self.config.smtp_host + ':' + self.config.smtp_port)

            server.quit()

            return connected

        except Exception as e:
            self.logger.error(MODULE_NAME + '::check_smtp_server_connection()::The following '
                                            'unhandled exception occurred: ' + e.message)
            connected = False
            return connected

    def smtp_send_email(self, row):

        try:
            sent = True

            while not self.config:
                time.sleep(1)

            # Grab values from row parameter
            first_name = row[1]
            last_name = row[2]
            requestor_email = row[3]
            data_requested = row[4]
            namespace_requested = row[5]
            bucket_name_requested = row[6]
            bucket_quota_requested = row[7]
            service_requested_processed = row[8]

            # Setup message object
            msg = email.message.Message()

            msg['Subject'] = "Dell Object Storage Provisioning Request - Update"
            msg['From'] = self.config.smtp_fromemail
            msg['To'] = self.config.smtp_toemail

            # if severity == 'WARNING':
            #     severity_text = """<font color="orange">""" + severity + "</font>"
            # else:
            #     if severity == 'ERROR':
            #         severity_text = """<font color="red">""" + severity + "</font>"
            #     else:
            #         if severity == 'CRITICAL':
            #             severity_text = """<font color="red">""" + severity + "</font>"
            #         else:
            #             severity_text = """<font color="black">""" + severity + "</font>"

            # Set email HTML content
            email_content = """
            <html>
            <head>
            <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
               <title>Dell Object Storage Provisioning Request - Update</title>
            </head> 
            <html><body><h1>Dell Object Storage Provisioning Request Processed for: {0} {1} </h1><br>
            Requestor Email : {2} <br> 
            Date Requested : {3} <br>
            Namespace Requested : {4}<br>
            Bucket Name Requested : {5}<br>
            Bucket Quota Requested : {6}<br>
            Service Request Processed : {7}<br>
            </body></html>"""

            # Format message
            msg.add_header('Content-Type', 'text/html')
            msg.set_payload(email_content.format(first_name, last_name, requestor_email, data_requested, namespace_requested, bucket_name_requested,bucket_quota_requested,service_requested_processed))

            # Connect to server and send email
            s = smtplib.SMTP(self.config.smtp_host + ':' + self.config.smtp_port)

            # If authentication is required please attempt to log in to the server with configured user and password
            if self.config.smtp_authentication_required == '1':
                s.login(self.config.smtp_user, self.config.smtp_password)

            # Send email
            s.sendmail(msg['From'], [msg['To']], msg.as_string())

            return sent

        except Exception as e:
            self.logger.error(MODULE_NAME + '::smtp_send_email()::The following '
                                            'unhandled exception occurred: ' + e.message)
            sent = False
            return sent
