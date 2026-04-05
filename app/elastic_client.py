# import os
# import urllib3
# from elasticsearch import Elasticsearch, RequestsHttpConnection
# from requests.auth import HTTPBasicAuth
# from dotenv import load_dotenv

# # Matikan warning SSL
# urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
# load_dotenv()

# ELASTIC_HOST = os.getenv("ELASTIC_HOST")
# ELASTIC_USER = os.getenv("ELASTIC_USER")
# ELASTIC_PASSWORD = os.getenv("ELASTIC_PASSWORD")

# print(f"Connecting to: {ELASTIC_HOST}")

# try:
#     # Gunakan connection class yang support requests + basic auth
#     es = Elasticsearch(
#         [ELASTIC_HOST],
#         connection_class=RequestsHttpConnection,
#         http_auth=(ELASTIC_USER, ELASTIC_PASSWORD),
#         use_ssl=True,
#         verify_certs=False
#     )

#     # Coba autentikasi
#     user_info = es.transport.perform_request("GET", "/_security/_authenticate")
#     print("✅ Connected as:", user_info["username"], "| Roles:", user_info["roles"])

# except Exception as e:
#     print("❌ Connection failed:", str(e))

# app/elastic_client.py
import os
import urllib3
from elasticsearch import Elasticsearch, RequestsHttpConnection
from dotenv import load_dotenv

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()

ELASTIC_HOST = os.getenv("ELASTIC_HOST")
ELASTIC_USER = os.getenv("ELASTIC_USER")
ELASTIC_PASSWORD = os.getenv("ELASTIC_PASSWORD")

es = None
elastic_connected = False
elastic_error = None

try:
    es = Elasticsearch(
        [ELASTIC_HOST],
        connection_class=RequestsHttpConnection,
        http_auth=(ELASTIC_USER, ELASTIC_PASSWORD),
        use_ssl=True,
        verify_certs=False,
        timeout=300
    )

    # 🔍 Ping ringan (lebih aman dari authenticate)
    if es.ping():
        elastic_connected = True
    else:
        elastic_error = "Ping failed"

except Exception as e:
    elastic_error = str(e)
    es = None


def get_elastic_status():
    """
    Helper untuk router
    """
    return {
        "connected": elastic_connected,
        "host": ELASTIC_HOST,
        "error": elastic_error
    }

