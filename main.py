import sys
import json
from datetime import datetime, timedelta, timezone
import requests
import os
from configparser import ConfigParser

config = ConfigParser()
config.read(config_file)
PROTECT_INSTANCE = "workjam"
CLIENT_ID = config.get('CLIENT_ID', 'key')
PASSWORD = onfig.get('PASSWORD', 'Password')

MIN_SEVERITY = "Low"  # Valid values: "Informational", "Low", "Medium", "High"
MAX_SEVERITY = "High"  # Valid values: "Informational", "Low", "Medium", "High"
JSON_OUTPUT_FILE = f"Jamf_Protect_Alerts_{datetime.utcnow().strftime('%Y-%m-%d')}.json"

from datetime import datetime, timedelta, timezone

def is_within_last_30_minutes(timestamp_str):
    input_timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
    current_timestamp = datetime.now(timezone.utc)
    time_difference = current_timestamp - input_timestamp

    return time_difference <= timedelta(minutes=30)



def get_access_token(protect_instance, client_id, password):
    """Gets a reusable access token to authenticate requests to the Jamf
    Protect API"""
    token_url = f"https://{protect_instance}.protect.jamfcloud.com/token"
    payload = {
        "client_id": client_id,
        "password": password,
    }
    resp = requests.post(token_url, json=payload)
    resp.raise_for_status()
    resp_data = resp.json()
    print(
        f"Access token granted, valid for {int(resp_data['expires_in'] // 60)} minutes."
    )
    return resp_data["access_token"]


def make_api_call(protect_instance, access_token, query, variables=None):
    """Sends a GraphQL query to the Jamf Protect API, and returns the
    response."""
    if variables is None:
        variables = {}
    api_url = f"https://{protect_instance}.protect.jamfcloud.com/graphql"
    payload = {"query": query, "variables": variables}
    headers = {"Authorization": access_token}
    resp = requests.post(
        api_url,
        json=payload,
        headers=headers,
    )
    resp.raise_for_status()
    return resp.json()


LIST_ALERTS_QUERY = """
        query listAlerts(
            $min_severity: SEVERITY
            $max_severity: SEVERITY
            $page_size: Int
            $next: String
        ) {
            listAlerts(
                input: {
                    filter: {
                        severity: { greaterThanOrEqual: $min_severity }
                        and: { severity: { lessThanOrEqual: $max_severity } }
                    }
                    pageSize: $page_size
                    next: $next
                }
            ) {
                items {
                        json
                        severity
                        computer {
                            hostName

                        }
                        created
                    }
                        pageInfo {
                                next
                    }
                }
            }
        """


def __main__():
    logfile = "/opt/wazuh_logging/jamf_pro/jamf_pro.log"
    if os.path.isfile(logfile):
        os.remove(logfile)
    if not set({MIN_SEVERITY, MAX_SEVERITY}).issubset(
            {"Informational", "Low", "Medium", "High"}
    ):
        print(
            "ERROR: Unexpected value(s) for min/max severity. Expected 'Informational', 'Low', 'Medium', or 'High'."
        )
        sys.exit(1)

    if not all([PROTECT_INSTANCE, CLIENT_ID, PASSWORD]):
        print("ERROR: Variables PROTECT_INSTANCE, CLIENT_ID, and PASSWORD must be set.")
        sys.exit(1)

    # Get the access token
    access_token = get_access_token(PROTECT_INSTANCE, CLIENT_ID, PASSWORD)

    results = []
    next_token = None
    page_count = 1
    # print("Retrieving paginated results:")
    while True:
        # print(f"  Retrieving page {page_count} of results...")
        vars = {
            "min_severity": MIN_SEVERITY,
            "max_severity": MAX_SEVERITY,
            "page_size": 200,
            "next": next_token,
        }
        resp = make_api_call(PROTECT_INSTANCE, access_token, LIST_ALERTS_QUERY, vars)
        alerts = resp["data"]["listAlerts"]["items"]
        with open(logfile, 'x') as logs_file:
            for alert in alerts:
                create_time = alert["created"]
                result = is_within_last_30_minutes(create_time)

                if result:
                    with open(logfile, "a") as write_file:
                        log = json.loads(alert["json"])
                        log['Log_type'] = 'Jamf_Pro'
                        json.dump(log, write_file)
                        write_file.write('\n')

                else:
                    print("The given timestamp is not within the last 30 minutes.")
                break
            next_token = resp["data"]["listAlerts"]["pageInfo"]["next"]
            # results.extend(resp["data"]["listAlerts"]["items"])
            if next_token is None:
                break
            page_count += 1


if __name__ == "__main__":
    __main__()
