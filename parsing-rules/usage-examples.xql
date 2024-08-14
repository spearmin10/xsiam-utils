/*
<14>1 2024-08-14T14:14:31+09:00 - - - - - CEF:0|Palo Alto Networks|Cortex XDR|Cortex XDR 3.11.0|XDR Analytics BIOC|Rare scheduled task created|6|end=1722914641722 shost=test-pc suser=['NT AUTHORITY\\\\SYSTEM'] deviceFacility=None cat=Persistence externalId=5907647 request=https://xdr20japan.xdr.us.paloaltonetworks.com/alerts/5907647 fs1=False fs1Label=Starred fs2=False fs2Label=Excluded cs1=schtasks.exe cs1Label=Initiated by cs2="schtasks.exe" /Change /TN "\\Microsoft\\Office\\IMESharePointDictionary" /TR "\\"c:\\Program Files\\Common Files\\Microsoft Shared\\IME16\\IMESharePointDictionary.exe\\" -updateall " cs2Label=Initiator CMD cs3=SIGNATURE_SIGNED-Microsoft Corporation cs3Label=Signature cs4=schtasks.exe cs4Label=CGO name cs5="schtasks.exe" /Change /TN "\\Microsoft\\Office\\IMESharePointDictionary" /TR "\\"c:\\Program Files\\Common Files\\Microsoft Shared\\IME16\\IMESharePointDictionary.exe\\" -updateall " cs5Label=CGO CMD cs6=SIGNATURE_SIGNED-Microsoft Corporation cs6Label=CGO Signature fileHash=f0024eb58326ecae6437237c3125ce75be6c621ea4b1303fd5b9dfe96b1dff32 filePath=C:\\Windows\\SysWOW64\\schtasks.exe targetprocesssignature=None-None tenantname=Palo Alto Networks - CoreCortex JAPAN - Cortex XDR tenantCDLid=1410944177 CSPaccountname=Palo Alto Networks - CoreCortex JAPAN initiatorSha256=f0024eb58326ecae6437237c3125ce75be6c621ea4b1303fd5b9dfe96b1dff32 initiatorPath=C:\\Windows\\SysWOW64\\schtasks.exe cgoSha256=f0024eb58326ecae6437237c3125ce75be6c621ea4b1303fd5b9dfe96b1dff32 osParentName=svchost.exe osParentCmd=C:\\WINDOWS\\system32\\svchost.exe -k netsvcs -p -s Schedule osParentSha256=949bfb5b4c7d58d92f3f9c5f8ec7ca4ceaffd10ec5f0020f0a987c472d61c54b osParentSignature=SIGNATURE_SIGNED osParentSigner=Microsoft Corporation act=Detected
*/
[INGEST:vendor="unknown", product="unknown", target_dataset="cef_cef_sample", no_hit=drop]
alter __log = _raw_log
| call minoue_syslog
| filter syslog != null

| alter cef = regexcapture(
    syslog->message,
    "CEF:\s*(?P<cef_version>\d+)\|(?P<cef_vendor>[^|]*)\|(?P<cef_product>[^|]*)\|(?P<dev_version>[^|]*)\|(?P<event_class_id>[^|]*)\|(?P<name>[^|]*)\|(?P<severity>[^|]*)\|(?P<extension>.*)$"
)
| filter cef->extension != ""

| alter __kvtext = trim(cef->extension)
| call minoue_nqsskv2kvobj

| alter extensions = _raw_kvobj->{}
| alter cef_version = cef->cef_version
| alter cef_vendor = cef->cef_vendor
| alter cef_product = cef->cef_product
| alter device_version = cef->dev_version
| alter event_class_id = cef->event_class_id
| alter name = cef->name
| alter severity = cef->severity
| fields cef_version, cef_vendor, cef_product, device_version, event_class_id, name, severity, extensions, _raw_log
;
