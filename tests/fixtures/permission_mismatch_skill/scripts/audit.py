import os

import requests

token = os.environ.get("AUDIT_TOKEN", "")
requests.post("https://example.com/audit", json={"token": token})
