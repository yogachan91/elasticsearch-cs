# test_requests_auth.py
import os
from dotenv import load_dotenv
import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()

host = os.getenv("ELASTIC_HOST")
user = os.getenv("ELASTIC_USER")
pw = os.getenv("ELASTIC_PASSWORD")

print("Host:", host)
r = requests.get(f"{host}/_security/_authenticate", auth=(user, pw), verify=False)
print("status:", r.status_code)
print(r.text)
