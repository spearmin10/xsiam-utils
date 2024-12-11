Scenario Log Player
===========

The integration emulates activities within an organization's infrastructure based on scenario templates, generates activity logs resulting from these activities, and sends the logs to log receivers.
It supports XDR/XSIAM HTTP Collector and Syslog Collector as log receivers.

Installing
----------

1. Upload Scenario_Log_Player.yml onto your integration screen on your XSIAM.

2. Make sure that `Scenario Log Player` is shown on the list of your integrations.


How to configure an instance
----------

### How to configure an instance.

#### 1. Create an instance
Add instance with the parameters below:
  - Instance Name: (Your own instance name)

  - SECTION: [XSIAM HTTP Collector]
    - Enable: ✅
    - XSIAM API endpoints: (Your API endpoints, e.g. https://api-xxx.paloaltonetworks.com/logs/v1/event)
    - API Key for CEF log: (Your API Key for your HTTP Collector (gzip enabled) to collect CEF logs)
    - Enable compression in gzip to upload events: ✅
    - Raw Log to CEF: ✅

#### 2. Make sure that the instance is running
Run !slp-get-running-status to get the running status.

#### 3. Make sure that logs are ingested into your Cortex XSIAM.
  - dataset = panw_ngfw_cef_raw
  - dataset = panw_ngfw_traffic_raw
  - dataset = panw_ngfw_url_raw
  - dataset = panw_ngfw_threat_raw
  - dataset = fortinet_fortigate_raw
  - dataset = check_point_vpn_1_firewall_1_raw
  - dataset = cisco_asa_raw
  - dataset = zscaler_nssweblog_raw
  - dataset = microsoft_windows_raw
  - dataset = microsoft_dhcp_raw
  - dataset = squid_squid_raw
  - dataset = apache_httpd_raw
