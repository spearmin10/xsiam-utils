/*********************************************************************
 *
 * Extract parameters from a CEF log
 *
 * e.g.
 * <14>1 2024-08-14T14:14:31+09:00 - - - - - CEF:0|Palo Alto Networks|Cortex XDR|Cortex XDR 3.11.0|XDR Analytics BIOC|Rare scheduled task created|6|end=1722914641722 shost=test-pc suser=['NT AUTHORITY\\\\SYSTEM'] deviceFacility=None cat=Persistence externalId=5907647 request=https://xdr20japan.xdr.us.paloaltonetworks.com/alerts/5907647 fs1=False fs1Label=Starred fs2=False fs2Label=Excluded cs1=schtasks.exe cs1Label=Initiated by cs2="schtasks.exe" /Change /TN "\\Microsoft\\Office\\IMESharePointDictionary" /TR "\\"c:\\Program Files\\Common Files\\Microsoft Shared\\IME16\\IMESharePointDictionary.exe\\" -updateall " cs2Label=Initiator CMD cs3=SIGNATURE_SIGNED-Microsoft Corporation cs3Label=Signature cs4=schtasks.exe cs4Label=CGO name cs5="schtasks.exe" /Change /TN "\\Microsoft\\Office\\IMESharePointDictionary" /TR "\\"c:\\Program Files\\Common Files\\Microsoft Shared\\IME16\\IMESharePointDictionary.exe\\" -updateall " cs5Label=CGO CMD cs6=SIGNATURE_SIGNED-Microsoft Corporation cs6Label=CGO Signature fileHash=f0024eb58326ecae6437237c3125ce75be6c621ea4b1303fd5b9dfe96b1dff32 filePath=C:\\Windows\\SysWOW64\\schtasks.exe targetprocesssignature=None-None tenantname=Palo Alto Networks - CoreCortex JAPAN - Cortex XDR tenantCDLid=1410944177 CSPaccountname=Palo Alto Networks - CoreCortex JAPAN initiatorSha256=f0024eb58326ecae6437237c3125ce75be6c621ea4b1303fd5b9dfe96b1dff32 initiatorPath=C:\\Windows\\SysWOW64\\schtasks.exe cgoSha256=f0024eb58326ecae6437237c3125ce75be6c621ea4b1303fd5b9dfe96b1dff32 osParentName=svchost.exe osParentCmd=C:\\WINDOWS\\system32\\svchost.exe -k netsvcs -p -s Schedule osParentSha256=949bfb5b4c7d58d92f3f9c5f8ec7ca4ceaffd10ec5f0020f0a987c472d61c54b osParentSignature=SIGNATURE_SIGNED osParentSigner=Microsoft Corporation act=Detected
 *
 ********************************************************************/
[INGEST:vendor="syslog", product="syslog", target_dataset="syslog_cef", no_hit=drop]
alter __log = _raw_log
| call minoue_parse_cef
| filter _cef != null

| alter cef_version = _cef->cef_version,
        device_vendor = _cef->dev_vendor,
        device_product = _cef->dev_product,
        device_version = _cef->dev_version,
        device_event_class_id = _cef->dev_event_class_id,
        name = _cef->name,
        severity = _cef->severity,
        extensions = _cef->extension.params{}
| fields _cef as cef, cef_version, device_vendor, device_product, device_version, device_event_class_id, name, severity, extensions, _raw_log
;

/*********************************************************************
 *
 * Extract parameters from a CSV log
 *
 * e.g.
 * <14>1 - - - - - - 1,2024/08/16 19:40:34,000099999999999,THREAT,url,2562,2024/08/16 19:40:34,192.168.1.59,192.168.1.50,0.0.0.0,0.0.0.0,Any,,,ssl,vsys1,cortex.lan,cortex.lan,ethernet1/1,ethernet1/1,My Logging,2024/08/16 19:40:34,6950,1,61630,636,0,0,0x10f400,tcp,allow,"cxj-ad.corp.cortex.lan:636/",9999(9999),private-ip-addresses,informational,client-to-server,7391530277083511466,0x8000000000000000,192.168.0.0-192.168.255.255,192.168.0.0-192.168.255.255,,,0,,,0,,,,,,,,0,0,0,0,0,,ngfw-apm,,,,,0,,0,,N/A,N/A,AppThreat-0-0,0x0,0,4294967295,,"private-ip-addresses",ce37e1dc-2ace-4425-99b8-6383ca48c765,0,,,,,,,,,,,,,,,,,,,,,,,,,,,,,0,2024-08-16T19:40:34.339+09:00,,,,encrypted-tunnel,networking,browser-based,4,"used-by-malware,able-to-transfer-file,has-known-vulnerability,tunnel-other-application,pervasive-use",,ssl,no,no
 *
 ********************************************************************/
[INGEST:vendor="syslog", product="syslog", target_dataset="syslog_csv", no_hit=drop]
alter __log = _raw_log
| call minoue_syslog
| filter _syslog != null

| alter __text = trim(_syslog->message) 
| filter __text ~= $PATTERN_CSV
| call minoue_csv2array
| alter params = to_json_string(_columns)
| alter _time = parse_timestamp("%Y/%m/%d %H:%M:%S", arrayindex(_columns, 1))
| alter serial_no = arrayindex(_columns, 2),
        type = arrayindex(_columns, 3),
        sub_type = arrayindex(_columns, 4),
        gen_time = arrayindex(_columns, 5),
        src = arrayindex(_columns, 6),
        dst = arrayindex(_columns, 7)
| fields _time, serial_no, type, sub_type, gen_time, src, dst, params
;
