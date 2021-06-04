import json
import logging
import os
import sys

import requests
from config import TOPIC_NAME, TOPIC_PROJECT_ID
from gobits import Gobits
from google.cloud import pubsub_v1
from utils import get_secret

logging.basicConfig(level=logging.INFO)


class AlertProcessor(object):
    def __init__(self):
        self.topic_name = TOPIC_NAME
        self.topic_project_id = TOPIC_PROJECT_ID
        self.project_id = os.environ.get("PROJECT_ID")
        if not self.project_id:
            logging.error("'PROJECT_ID' environment variable is not set")
            sys.exit(1)
        self.github_token_secret_id = os.environ.get("GITHUB_TOKEN_SECRET_ID")
        if not self.github_token_secret_id:
            logging.error("'GITHUB_TOKEN_SECRET_ID' environment variable is not set")
            sys.exit(1)

    def process(self, payload):
        alerts = payload["github-issues"]
        gobits_metadata = payload["gobits"]
        for alert in alerts:
            if self.process_alert(alert, gobits_metadata) is False:
                logging.info("Message not processed")
            else:
                logging.info("Message is processed")

    def process_alert(self, alert, gobits_metadata):
        dependabot_alert = self.get_dependabot_alerts(alert)
        dependabot_messages = self.create_messages(alert, dependabot_alert)
        if not dependabot_messages:
            logging.info(
                f"No dependabot alerts were found on repository {alert['repository']}"
            )
            return True
        metadata = [Gobits().to_json()]
        metadata.append(gobits_metadata)
        for dependabot_message in dependabot_messages:
            return_bool_publish_topic = self.publish_to_topic(
                dependabot_message, metadata
            )
            if not return_bool_publish_topic:
                return False
        return True

    def get_dependabot_alerts(self, alert):
        token = get_secret(self.project_id, self.github_token_secret_id)
        header = {"Authorization": f"Bearer {token}"}
        repository_list = alert["repository"].split("/")
        # The GraphQL query (with a few aditional bits included) itself defined as a multi-line string.
        query = (
            "{"
            f'    repository(name: "{repository_list[1]}", owner: "{repository_list[0]}") {{'
            "        vulnerabilityAlerts(first: 100) {"
            "            nodes {"
            "                createdAt"
            "                dismissedAt"
            "                vulnerableManifestFilename"
            "                vulnerableManifestPath"
            "                securityVulnerability {"
            "                    package {"
            "                        name"
            "                    }"
            "                    advisory {"
            "                        description"
            "                    }"
            "                }"
            "            }"
            "        }"
            "    }"
            "}"
        )
        dependabot_alert = self.run_query(query, header)
        return dependabot_alert

    def run_query(
        self, query, headers
    ):  # A function to use requests.post to make the API call. Note the json= section.
        request = requests.post(
            "https://api.github.com/graphql", json={"query": query}, headers=headers
        )
        if request.status_code == 200:
            return request.json()
        else:
            raise Exception(
                "Query failed to run by returning code of {}. {}".format(
                    request.status_code, query
                )
            )

    def create_messages(self, alert, dependabot_alert):
        messages = []
        dependabot_nodes = dependabot_alert["data"]["repository"][
            "vulnerabilityAlerts"
        ]["nodes"]
        for node in dependabot_nodes:
            if node["securityVulnerability"]["package"]["name"] == alert["package"]:
                message = {
                    "repository": alert["repository"],
                    "vulnerable_manifest_path": node["vulnerableManifestPath"],
                    "package": alert["package"],
                    "fixed_in": alert["package"],
                    "advisory": node["securityVulnerability"]["advisory"][
                        "description"
                    ],
                    "created_at": node["createdAt"],
                    "dismissed_at": node["dismissedAt"],
                }
                messages.append(message)
        return messages

    def publish_to_topic(self, message, gobits):
        date = ""
        if "received_on" in message:
            date = message["received_on"]
        msg = {"gobits": [gobits], "parsed_alert": message}
        try:
            # Publish to topic
            publisher = pubsub_v1.PublisherClient()
            topic_path = "projects/{}/topics/{}".format(
                self.topic_project_id, self.topic_name
            )
            future = publisher.publish(
                topic_path, bytes(json.dumps(msg).encode("utf-8"))
            )
            if date:
                future.add_done_callback(
                    lambda x: logging.debug("Published parsed github alert")
                )
            future.add_done_callback(
                lambda x: logging.debug("Published parsed github alert")
            )
            logging.info("Published parsed github alert")
            return True
        except Exception as e:
            logging.exception(
                "Unable to publish parsed github alert "
                + "to topic because of {}".format(e)
            )
        return False
