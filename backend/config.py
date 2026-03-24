import os


WAZUH_API_URL = os.getenv("WAZUH_API_URL", "https://192.168.33.207:55000")
WAZUH_USER = os.getenv("WAZUH_API_USER", "wazuh")
WAZUH_PASSWORD = os.getenv("WAZUH_API_PASSWORD", "wazuh")
