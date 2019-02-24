import json
import logging

import json
import logging
import os

from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# The log level
log_level = os.environ['log_level'].upper()

root_alert_level  = os.environ['root_alert_level']
mfa_alert_level     = os.environ['mfa_alert_level']
failed_alert_level = os.environ['failed_alert_level']
user_alert_level = os.environ['user_alert_level']

high_hook_url   = os.environ['high_hook_url']
medium_hook_url = os.environ['medium_hook_url']
low_hook_url    = os.environ['low_hook_url']

high_channel   = os.environ['high_channel']
medium_channel = os.environ['medium_channel']
low_channel    = os.environ['low_channel']

logger = logging.getLogger()
logger.setLevel(log_level)

def push_slack(slack_request):
    hook_url = slack_request['hook_url']
    slack_message =slack_request['msg']
    
    req = Request(hook_url, json.dumps(slack_message).encode('utf-8'))
    
    try:
      response = urlopen(req)
      response.read()
      logger.info("Message posted to %s", slack_message['channel'])
    except HTTPError as e:
      logger.error("Request failed: %d %s", e.code, e.reason)
    except URLError as e:
      logger.error("Server connection failed: %s", e.reason)

def check_event(detail):
    
    slack_request = {}
    event_name = detail['eventName']
    login_type = detail['userIdentity']['type']
    arn = detail['userIdentity']['arn']
    login_status = detail['responseElements']['ConsoleLogin']
    mfa_status = detail['additionalEventData']['MFAUsed']
    parameters = detail['requestParameters']
    if login_status != 'Success':
        event_name = event_name + " " + login_status
        if failed_alert_level == "High":
            hook_url = high_hook_url
            channel = high_channel
            color = "#8b0000"
        elif failed_alert_level == "Medium":
            hook_url = medium_hook_url
            channel = medium_channel
            color = "#ff8c00"
        elif failed_alert_level == "low":
            hook_url =low_hook_url
            channel = low_channel
            color = "#fafad2"
        
    elif mfa_status != 'Yes':
        event_name = event_name + " MFA status: " + mfa_status
        if mfa_alert_level == "High":
            hook_url = high_hook_url
            channel = high_channel
            color = "#8b0000"
        elif mfa_alert_level == "Medium":
            hook_url = medium_hook_url
            channel = medium_channel
            color = "#ff8c00"
        elif mfa_alert_level == "low":
            hook_url =low_hook_url
            channel = low_channel
            color = "#fafad2"
            
    elif login_type == 'Root':
        event_name = event_name + " as Root"
        if root_alert_level == "High":
            hook_url = high_hook_url
            channel = high_channel
            color = "#8b0000"
        elif root_alert_level == "Medium":
            hook_url = medium_hook_url
            channel = medium_channel
            color = "#ff8c00"
        elif root_alert_level == "low":
            hook_url =low_hook_url
            channel = low_channel
            color = "#fafad2"
        
    else:
        if user_alert_level == "High":
            hook_url = high_hook_url
            channel = high_channel
            color = "#8b0000"
        elif user_alert_level == "Medium":
            hook_url = medium_hook_url
            channel = medium_channel
            color = "#ff8c00"
        elif user_alert_level == "low":
            hook_url =low_hook_url
            channel = low_channel
            color = "#fafad2"
            
    slack_request = {
        "hook_url" : hook_url,
        "msg" : {
          "channel" : channel,
          "username" : "AWS:Console login alert",
          "text" : "*Action: %s*" % (event_name),
          "attachments": [
              {
                "color": color,
                "fields": [
                    {
                        "title": "User ARN",
                        "value": arn,
                        "short": True
                    },
                    {
                        "title": "MFA status",
                        "value": mfa_status,
                        "short": True
                    },
                    {
                        "title": "Detail parameters",
                        "value": str(parameters)
                    }
                ],
              }
            ]
        }
    }
    return slack_request

def lambda_handler(event, context):
    logger.info("Event: " + str(event))
    
    detail = event['detail']
    logger.info("Detail: " + str(detail))

    slack_request = check_event(detail)
    if slack_request == None:
        pass
    else:
        push_slack(slack_request)
    
    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda!')
    }

