Splunk Log Ingester
===========

This integration forwards logs from Splunk to XSIAM HTTP Collector.

Installing
----------

1. Upload Splunk_Log_Ingester.yml onto your integration screen on your XSIAM.

2. Make sure that `Splunk Log Ingester` is shown on the list of your integrations.


How to configure an instance
----------

#### 1. Create an instance
Enter required parameters to connect to XSIAM and Splunk.
In addition to make sure that `Long running instance` is enabled.
  - Long running instance: [enabled]

#### 2. Check the forwarding process running
Run !splunkli-get-last-run to make sure that the process is running.

### NOTE:
 - !splunk-reset-last-run allows you to restart the log forwarding in a minute from the first fetch timestamp.
