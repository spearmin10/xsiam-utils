/***
 * This expression transforms a comma separated value to an array.
 * This is compatible with the `minoue_csv2array` rule.
 *
 * The standard pattern is:
 *    value[,value]*
 *
 *  e.g.
 *    val1,val2,val3
 *
 * ### Supported Syntax/Formats
 *  - A backslash charator escapes a following charactor.
 *  - 'value' can be quoted with a double quotation mark.
 *  - A double double quotation marks ("") in the quoted value is converted to a single double quotation mark.
 *  - Any spaces can be allowed between a value and a comma separator.
 *
 *   e.g.
 *    - "value"
 *    - va\ lue
 *    - va\\lue
 *    - va\"lue
 *    - va\,lue
 *    - "va,lue"
 *    - "va""lue"
 *    - val1 , val2 , val3
 *    - " val1 " , " val2 " , val3
 *
 * You will get unexpected results if you give a text containing incorrect patterns as it doesn't check it.
 * You should ensure the text in the correct format with the PATTERN_CSV in advance if needed.
 *
 * PATTERN_CSV = "^\s*(?:(?:\"(?:\"\"|\\.|[^\\\"])*\")|[^,\"]*?)\s*(?:,\s*(?:(?:\"(?:\"\"|\\.|[^\\\"])*\")|[^,\"]*?)\s*)*$"
 *
 * :param __text: A comma separated text
 * :return _columns: Array of column values
 *
 * @auther Masahiko Inoue
 ***/

//
// Sample Texts
//
dataset = xdr_data
| limit 1
| alter __text = arraycreate(
    """1,2024/08/16 19:40:34,000099999999999,THREAT,url,2562,2024/08/16 19:40:34,192.168.1.59,192.168.1.50,0.0.0.0,0.0.0.0,Any,,,ssl,vsys1,cortex.lan,cortex.lan,ethernet1/1,ethernet1/1,My Logging,2024/08/16 19:40:34,6950,1,61630,636,0,0,0x10f400,tcp,allow,\"cxj-ad.corp.cortex.lan:636/\",9999(9999),private-ip-addresses,informational,client-to-server,7391530277083511466,0x8000000000000000,192.168.0.0-192.168.255.255,192.168.0.0-192.168.255.255,,,0,,,0,,,,,,,,0,0,0,0,0,,ngfw-apm,,,,,0,,0,,N/A,N/A,AppThreat-0-0,0x0,0,4294967295,,\"private-ip-addresses\",ce37e1dc-2ace-4425-99b8-6383ca48c765,0,,,,,,,,,,,,,,,,,,,,,,,,,,,,,0,2024-08-16T19:40:34.339+09:00,,,,encrypted-tunnel,networking,browser-based,4,\"used-by-malware,able-to-transfer-file,has-known-vulnerability,tunnel-other-application,pervasive-use\",,ssl,no,no""",
    """\"value\"""",
    """va\\ lue""",
    """va\\\\lue""",
    """va\\\"lue""",
    """va\\,lue""",
    """\"va,lue\"""",
    """\"va\"\"lue\"""",
    """val1 , val2 , val3""",
    """\" val1 \" , \" val2 \" , val3"""
)
| arrayexpand __text

//
// Run
//
| alter _columns = arraymap(
     regextract(
         replace(to_string(coalesce(__text, "")), ",", ",,"),
         "(?:^|,)\s*(?:\"(?:\"\"|\\.|[^\"])*\"|(?:\\,,|\\[^,]|[^,\\])*)\s*(?:,|$)"
     ),
     arrayindex(
         arraymap(
             arraymap(
                 arraycreate(replace("@element", ",,", ",")),
                 arrayindex(
                     if(
                         "@element" ~= "^\s*,?\s*\"((?:\\.|[^\"])*)\"\s*,?\s*$",
                         regextract("@element", "^\s*,?\s*\"((?:\\.|[^\"])*)\"\s*,?\s*$"),
                         regextract("@element", "^\s*,?\s*((?:\\.|[^,])*)\s*,?\s*$")
                     ),
                     0
                 )
             ),
             arraystring(
                 arraymap(
                     split("@element", """\\\\"""),
                     replace(replace("@element", """\\""", ""), "\"\"", "\"")
                 ),
                 """\\"""
             )
         ),
         0
     )
)

/**********
//
// 1-line
//

| alter _columns = arraymap(regextract(replace(to_string(coalesce(__text, "")), ",", ",,"),"(?:^|,)\s*(?:\"(?:\"\"|\\.|[^\"])*\"|(?:\\,,|\\[^,]|[^,\\])*)\s*(?:,|$)"),arrayindex(arraymap(arraymap(arraycreate(replace("@element", ",,", ",")),arrayindex(if("@element" ~= "^\s*,?\s*\"((?:\\.|[^\"])*)\"\s*,?\s*$",regextract("@element", "^\s*,?\s*\"((?:\\.|[^\"])*)\"\s*,?\s*$"),regextract("@element", "^\s*,?\s*((?:\\.|[^,])*)\s*,?\s*$")),0)),arraystring(arraymap(split("@element", """\\\\"""),replace(replace("@element", """\\""", ""), "\"\"", "\"")),"""\\""")),0))

**********/

| fields __text, _columns
