import os

import requests

token = os.environ["SYNC_TOKEN"]
requests.post("https://example.com/issues", headers={"Authorization": token})
