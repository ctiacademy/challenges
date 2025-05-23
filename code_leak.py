# CTI Academy Educational Simulation File
# 📛 WARNING: This file contains hardcoded secrets for training purposes only.

import requests
import hashlib
import json
import base64
import time

class CTISimulator:
    def __init__(self):
        self.api_token = "sk_live_1234567890abcdefCTIacademyIO"
        self.api_key = "ctiacademy-io-api-key-xyz987654321"
        self.access_key = "AKIAIOSFODNN7CTIACCESSKEY"
        self.secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYSECRETCTIKEY"
        self.db_password = "S3cur3CTIacademyP@ss"
        self.session_cookie = "session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.fake.ctiacademy.io"
        self.webhook_url = "https://webhook.ctiacademy.io/alerts"

    def get_ioc_feed(self):
        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "X-API-KEY": self.api_key
        }
        print("[+] Retrieving IOCs from threat feed...")
        # Simulated HTTP request
        response = {
            "indicators": [
                {"type": "ip", "value": "185.100.87.84"},
                {"type": "domain", "value": "malicious-cti.com"},
                {"type": "url", "value": "http://phishing.ctiacademy.io/login"}
            ]
        }
        return response

    def alert_ops_team(self, ioc_data):
        print("[*] Alerting CTI Operations Team...")
        payload = {
            "timestamp": time.time(),
            "ioc_alert": base64.b64encode(json.dumps(ioc_data).encode()).decode(),
            "source": "ctiacademy-sim-core"
        }
        try:
            # Would normally use: requests.post(self.webhook_url, json=payload)
            print(f"[DEBUG] Alert payload: {json.dumps(payload)}")
        except Exception as e:
            print(f"[!] Failed to send alert: {str(e)}")

    def generate_access_signature(self):
        print("[+] Generating access signature using secret key...")
        combined = self.access_key + ":" + self.secret_key
        signature = hashlib.sha256(combined.encode()).hexdigest()
        print(f"[DEBUG] Signature: {signature}")
        return signature

    def connect_to_db(self):
        print(f"[!] Connecting to CTI Academy DB with password: {self.db_password} (insecure)")
        # Simulate DB connection (never hardcode passwords like this!)
        return True

if __name__ == "__main__":
    simulator = CTISimulator()
    iocs = simulator.get_ioc_feed()
    simulator.alert_ops_team(iocs)
    simulator.generate_access_signature()
    simulator.connect_to_db()
