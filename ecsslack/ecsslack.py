"""
DELL EMC ECS Slack Delivery Module
"""

import json
import requests
import time

# Constants
MODULE_NAME = "ecsslack"  # Module Name


class ECSSlackException(Exception):
    pass


class ECSSlackUtility(object):
    """
    Stores ECS Slack Delivery Functions
    """

    def __init__(self, config, logger):
        self.config = config
        self.logger = logger

    def slack_send_message(self, row):

        try:
            while not self.config:
                time.sleep(1)

            # Grab values from row parameter
            vdc = row[1]
            management_ip = row[2]
            management_ip_link = 'https://' + row[2]
            description = row[5]
            severity = row[7]
            symtomcode = row[8]
            timestamp = row[9]

            if severity == 'WARNING':
                severity_color = "#FFA500"
            else:
                if severity == 'ERROR':
                    severity_color = "#FF0000"
                else:
                    if severity == 'INFO':
                        severity_color = "#008000"
                    else:
                        if severity == 'CRITICAL':
                            severity_color = "#FF0000"
                        else:
                            severity_color = "#000000"

            # Set email HTML content
            message_json = '''{{
                'attachments': [
                    {{
                        "fallback": "ECS Alert Received From VDC: *{0}*",
                        "color": "{1}",
                        "pretext": "ECS Alert Received From VDC: *{2}*",
                        "title": "ECS Cluster: {3}",
                        "title_link": "{4}",
                        "text": "Alert Details:",
                        "fields": [
                            {{
                                "title": "Severity ",
                                "value": "{5}",
                                "short": True
                            }},
                            {{
                                "title": "Symptom Code ",
                                "value": "{6}",
                                "short": True
                            }},
                            {{
                                "title": "Description ",
                                "value": "{7}",
                                "short": True
                            }},
                            {{
                                "title": "Timestamp ",
                                "value": "{8}",
                                "short": True
                            }}
                        ],
                        "footer": "Slack API",
                        "footer_icon": "https://platform.slack-edge.com/img/default_application_icon.png"
                     }}
                ]
            }}'''

            # Perform Perform call t Slack API
            headers = {'content-type': 'application/json'}

            test = message_json.format(vdc, severity_color, vdc, management_ip, management_ip_link, severity,
                                       symtomcode, description, timestamp)

            r = requests.post(self.config.slack_webhook, data=test, headers=headers, verify=False)

            if r.status_code == requests.codes.ok:
                self.logger.debug(MODULE_NAME + 'slack_send_message()::'
                                  + self.config.slack_webhook + ' call returned '
                                                                'with a 200 status code.')
                sent = True
            else:
                self.logger.error(MODULE_NAME + 'slack_send_message()::' + self.config.slack_webhook +
                                  ' call failed with a status code of ' + str(r.status_code))
                sent = False

            return sent

        except Exception as e:
            self.logger.error(MODULE_NAME + '::slack_send_message()::The following '
                                            'unhandled exception occurred: ' + e.message)
            sent = False
            return sent
