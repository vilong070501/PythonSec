import json

LOG_TYPE_MAPPING = {
    1000: "LOG_BASE_BOOT",
    1001: "LOG_BASE_MSG",
    1002: "LOG_BASE_DEBUG",
    1003: "LOG_BASE_ERROR",
    1004: "LOG_BASE_PING",
    1005: "LOG_BASE_CONFIG_SAVE",
    1006: "LOG_BASE_EXAMPLE",
    2000: "LOG_FTP_LOGIN_ATTEMPT",
    2001: "LOG_FTP_AUTH_ATTEMPT_INITIATED",
    3000: "LOG_HTTP_GET",
    3001: "LOG_HTTP_POST_LOGIN_ATTEMPT",
    3002: "LOG_HTTP_UNIMPLEMENTED_METHOD",
    3003: "LOG_HTTP_REDIRECT",
    4000: "LOG_SSH_NEW_CONNECTION",
    4001: "LOG_SSH_REMOTE_VERSION_SENT",
    4002: "LOG_SSH_LOGIN_ATTEMPT",
    5000: "LOG_SMB_FILE_OPEN",
    5001: "LOG_PORT_SYN",
    5002: "LOG_PORT_NMAPOS",
    5003: "LOG_PORT_NMAPNULL",
    5004: "LOG_PORT_NMAPXMAS",
    5005: "LOG_PORT_NMAPFIN",
    6001: "LOG_TELNET_LOGIN_ATTEMPT",
    6002: "LOG_TELNET_CONNECTION_MADE",
    7001: "LOG_HTTPPROXY_LOGIN_ATTEMPT",
    8001: "LOG_MYSQL_LOGIN_ATTEMPT",
    9001: "LOG_MSSQL_LOGIN_SQLAUTH",
    9002: "LOG_MSSQL_LOGIN_WINAUTH",
    9003: "LOG_MYSQL_CONNECTION_MADE",
    10001: "LOG_TFTP",
    11001: "LOG_NTP_MONLIST",
    12001: "LOG_VNC",
    13001: "LOG_SNMP_CMD",
    14001: "LOG_RDP",
    15001: "LOG_SIP_REQUEST",
    16001: "LOG_GIT_CLONE_REQUEST",
    17001: "LOG_REDIS_COMMAND",
    18001: "LOG_TCP_BANNER_CONNECTION_MADE",
    18002: "LOG_TCP_BANNER_KEEP_ALIVE_CONNECTION_MADE",
    18003: "LOG_TCP_BANNER_KEEP_ALIVE_SECRET_RECEIVED",
    18004: "LOG_TCP_BANNER_KEEP_ALIVE_DATA_RECEIVED",
    18005: "LOG_TCP_BANNER_DATA_RECEIVED",
    19001: "LOG_LLMNR_QUERY_RESPONSE",
    99000: "LOG_USER_0",
    99001: "LOG_USER_1",
    99002: "LOG_USER_2",
    99003: "LOG_USER_3",
    99004: "LOG_USER_4",
    99005: "LOG_USER_5",
    99006: "LOG_USER_6",
    99007: "LOG_USER_7",
    99008: "LOG_USER_8",
    99009: "LOG_USER_9",
}

def parse_logs(log_file):
    log_data = "{"
    i = 0
    try:
        with open(log_file, 'r') as f:
            logs = f.readlines()
            for line in logs:
                log_entry = json.loads(line)
                attack_type = classify_attack(log_entry["logtype"])
                log_data += "\"" + str(i) + "\": " +"{\"Attack Detected\": \"" + attack_type + "\","
                log_data += "\"Details\": " + str(log_entry).replace("'", "\"") + "},"
                i += 1
            log_data = log_data[:-1] + "}"
            with open('log_data.json', 'w') as json_file:
                json_file.write(json.dumps(json.loads(log_data), indent=4))
    except FileNotFoundError:
        print(f"Log file {log_file} not found.")
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")

def classify_attack(log_type):
    return LOG_TYPE_MAPPING.get(log_type, "Unknown Log Type")

if __name__ == "__main__":
    log_file = "/var/tmp/opencanary.log"
    parse_logs(log_file)
