/* *******************************************************
 * MINOUE Parsing Rules Library
 *
 * @auther Masahiko Inoue
 * @url https://github.com/spearmin10/xsiam-utils/blob/main/parsing-rules/minoue-parsing-rules.xql
 * ******************************************************/
[CONST]
PATTERN_CSKV = "^(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^,=\"\s])+)\s*?=\s*?(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^,\"\s])*)(?:,\s*(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^,=\"\s])+)\s*=\s*(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^,\"\s])*))*$";
PATTERN_SSKV = "^(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^=\"\s])+)\s*?=\s*?(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^\"\s])*)(?:\s\s*(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^=\"\s])+)\s*=\s*(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^\"\s])*))*$";
PATTERN_CSV = "^\s*(?:(?:\"(?:\"\"|\\.|[^\\\"])*\")|[^,\"]*?)\s*(?:,\s*(?:(?:\"(?:\"\"|\\.|[^\\\"])*\")|[^,\"]*?)\s*)*$";
PATTERN_IPV4 = "^(?:(?:25[0-5]|(?:2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$";

[RULE: minoue_cskv2kvobj]
/***
 * This rule transforms a comma separated key=value text to a json object.
 * The standard pattern is:
 *    key=value[, key=value]*
 *
 *   e.g.
 *    - key1=val1, key2=val2, key3=val3
 *
 * 'key' and 'value' can be quoted with a double quotation mark, 'key' and 'value' between '=' allows any spaces to be inserted,
 * and also a back-slash escapes a following charactor in quoted text.
 *   e.g.
 *    - "key"="value"
 *    - key = value
 *    - key = "value"
 *    - "k\"ey" = "va\\lue"
 *
 * If `value` doesn't include the delimiter which is ',', it supports to transform from a spaces separated text.
 *   e.g.
 *    - key1=value1 key2=value2 key3=value3
 *
 * If `value` is quoted with a double quotation mark, it supports text separated with any delimiters and without a delimiter.
 *
 *   e.g.
 *    - key1="v a l 1" key2="v a l 2", key3=val3
 *    - key1="v a l 1"key2="v a l 2"
 *    - key1="v a l 1""key2"="v a l 2"
 *
 * You will get unexpected results if you give a text containing incorrect patterns as it doesn't check it.
 * You should ensure the text in the correct format with $PATTERN_CSKV in advance.
 * On the contrary, it will successfully return a JSON object without raising errors even if the text contains incorrect patterns.
 * You can give any texts if you want. It recommends to use `_raw_kvobj->{}` to get the entire JSON object in order to check if the return value is in the correct JSON object in case of incorrect text to be returned.
 *
 * :param __kvtext: A comma separated key=value text
 * :return _raw_kvobj: JSON object text
 *
 * @auther Masahiko Inoue
 * @url https://github.com/spearmin10/xsiam-utils/blob/main/parsing-rules/minoue-parsing-rules.xql
 ***/
alter _raw_kvobj = format_string(
    "{%s}",
    arraystring(
        arraymap(
            regextract(
                to_string(coalesce(__kvtext, "")),
                "(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^,=\"\s])+)\s*?=\s*(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^,\s])*)"
            ),
            arrayindex(
                arraymap(
                    arraycreate(
                        regexcapture(to_string("@element"), "^\"?(?P<key>(?:\\.|[^\\\"])*?)\"?\s*?=\s*\"?(?P<val>.*?)\"?$")
                    ),
                    format_string(
                        "\"%s\"",
                        arraystring(
                            arraymap(
                                arraycreate(lowercase("@element"->key), "@element"->val),
                                // Escape backsrashs and double quotations
                                replace(
                                    replace(
                                        // Unescape escaped charactors
                                        arraystring(arraymap(split("@element", """\\\\"""), replace("@element", """\\""", "")), """\\"""),
                                        """\\""", """\\\\"""
                                    ),
                                    """\"""", """\\\""""
                                )
                            ),
                            "\":\""
                        )
                    )
                ),
                0
            )
        ),
        ","
    )
)
;

[RULE: minoue_sskv2kvobj]
/***
 * This rule transforms a space separated key=value text to a json object.
 * The standard pattern is:
 *    key=value[ key=value]*
 *
 *  e.g.
 *    - key1=val1 key2=val2 key3=val3
 *
 * 'key' and 'value' can be quoted with a double quotation mark, 'key' and 'value' between '=' allows any spaces to be inserted,
 * and also a back-slash escapes a following charactor in quoted text.
 *   e.g.
 *    - "key"="value"
 *    - key = value
 *    - key = "value"
 *    - "k\"ey" = "va\\lue"
 *
 * If `value` is quoted with a double quotation mark, it supports text separated with any delimiters and without a delimiter.
 *
 *   e.g.
 *    - key1="v a l 1" key2="v a l 2", key3=val3
 *    - key1="v a l 1"key2="v a l 2"
 *    - key1="v a l 1",key2="v a l 2"
 *    - key1="v a l 1""key2"="v a l 2"
 *    - key1="v a l 1","key2"="v a l 2"
 *
 * You will get unexpected results if you give a text in incorrect patterns as it doesn't check it.
 * You should ensure the text in the correct format with $PATTERN_SSKV.
  * On the contrary, it will successfully return a JSON object without raising errors even if the text contains incorrect patterns.
 * You can give any texts if you want. It recommends to use `_raw_kvobj->{}` to get the entire JSON object in order to check if the return value is in the correct JSON object in case of incorrect text to be returned.
 *
 * :param __kvtext: A space separated key=value text
 * :return _raw_kvobj: JSON object text
 *
 * @auther Masahiko Inoue
 * @url https://github.com/spearmin10/xsiam-utils/blob/main/parsing-rules/minoue-parsing-rules.xql
 ***/
alter _raw_kvobj = format_string(
    "{%s}",
    arraystring(
        arraymap(
            regextract(
                to_string(coalesce(__kvtext, "")),
                "(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^=\"\s])+)\s*?=\s*(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^\s])*)"
            ),
            arrayindex(
                arraymap(
                    arraycreate(
                        regexcapture(to_string("@element"), "^\"?(?P<key>(?:\\.|[^\\\"])*?)\"?\s*?=\s*\"?(?P<val>.*?)\"?$")
                    ),
                    format_string(
                        "\"%s\"",
                        arraystring(
                            arraymap(
                                arraycreate(lowercase("@element"->key), "@element"->val),
                                // Escape backsrashs and double quotations
                                replace(
                                    replace(
                                        // Unescape escaped charactors
                                        arraystring(arraymap(split("@element", """\\\\"""), replace("@element", """\\""", "")), """\\"""),
                                        """\\""", """\\\\"""
                                    ),
                                    """\"""", """\\\""""
                                )
                            ),
                            "\":\""
                        )
                    )
                ),
                0
            )
        ),
        ","
    )
)
;

[RULE: minoue_nqsskv2kvobj]
/***
 * This rule transforms a space separated key=value text to a json object.
 * The standard pattern is:
 *    key=value[ key=value]*
 *
 *  e.g.
 *    key1=val1 key2=val2 key3=val3
 *
 * ### Supported Syntax/Formats
 *  - A back-slash charator escapes a following charactor.
 *  - 'key' and 'value' can be quoted with a double quotation mark.
 *  - 'value' can contain spaces regardless the quoted text.
 *  - 'value' can contain multiple tokens quoted with a double quotation mark.
 *  - 'value' can be an empty value regardless the quoted text.
 *  - 'key' can contain any spaces only when it's quoted or a space in it is escaped.
 *  - 'key' and 'value' between '=' allows any spaces to be inserted.
 *  - 'key' of the next key=value can be placed immediately after the current key=value without any spaces when at least one of the current 'value' or the next 'key' is quoted.
 * 
 *   e.g.
 *    - key1="val1" key2="val2"
 *    - key1="val=1" key2="val=2"
 *    - key1="va\\l1" key2="va\\l2"
 *    - key1=v a l 1 key2=v a l 2
 *    - "key1"="val1" "key2"="val2"
 *    - key1 = val1 key2 = val2
 *    - key1 = val1 key2 = "v a l 2"
 *    - key1=val\=1 key2=val\=2
 *    - "k e y 1" = "v a l 1"key2 = "v a l 2"
 *    - "k e y 1" = val1"k e y 2" = "v a l 2"
 *    - "k e y 1" = "v a l 1" "k e y 2" = "v a l 2"
 *    - "k e y 1" = "v a l 1""k e y 2" = "v a l 2"
 *    - key1="v1[1]" v1[2] "v1[3]" key2=v2[1] "v2[2]"
 *    - key1="" key2= key3=
 *
 * You will get unexpected results if you give a text in incorrect patterns as it doesn't check it.
 * It's responsible for you to ensure the text in the correct format before giving it,
 * however you wouldn't be able to check the pattern only with RE2.
 * You can give any texts if you want. It recommends to use `_raw_kvobj->{}` to get the entire JSON object in order to check if the return value is in the correct JSON object in case of incorrect text to be returned.
 *
 * :param __kvtext: A space separated key=value text
 * :return _raw_kvobj: JSON object text
 *
 * @auther Masahiko Inoue
 * @url https://github.com/spearmin10/xsiam-utils/blob/main/parsing-rules/minoue-parsing-rules.xql
 ***/
alter _raw_kvobj = format_string(
    "{%s}",
    arraystring(
        arraymap(
            regextract(
                replace(to_string(coalesce(__kvtext, "")), "=", "=="),
                "=(?:\"(?:\\==|\\.|[^\\\"])*\"|(?:\\==|\\[^=\"]|[^=\\\"]))+?=|^(?:\"(?:\\==|\\.|[^\\\"])*\"|(?:\\==|\\[^=\"]|[^=\\\"]))*?=|=(?:\"(?:\\==|\\.|[^\\\"])*\"|(?:\\==|\\[^=\"]|[^=\\\"]))*?$"
            ),
            arrayindex(
                arraymap(
                    arraymap(
                        arraycreate(
                            regexcapture(to_string("@element"), "^(?:=\s*(?P<vkv>(?:\"(?:\\==|\\[^=]|[^\\\"])*\"|(?:\\==|\\[^=]|[^\\\"=]))*?)\s*(?P<vkk>\"(?:\\==|\\[^=]|[^\\\"])*\"|(?:(?:\\==|\\[^=]|[^\\\"=\s])+))\s*=|\s*(?P<fk>\"(?:\\.|[^\\\"])*\"|(?:(?:\\==|\\[^=]|[^\\\"=])+))\s*=|=\s*(?P<lv>(?:\"(?:\\==|\\[^=]|[^\\\"])*\"|(?:\\==|\\[^=]|[^\\\"=]))*?)\s*)$")
                        ),
                        object_create(
                            "x",
                            arraymap(
                                arraymap(
                                    arraymap(
                                        if(
                                            "@element"->vkk != "",
                                            arraycreate("@element"->vkv, "@element"->vkk),
                                            if("@element"->fk != "", arraycreate("@element"->fk), arraycreate("@element"->lv))
                                        ),
                                        regexcapture(replace("@element", "==", "="), "^(?:\"(?P<qv>(?:\\.|[^\"])*)\"|(?P<nv>.*))$")
                                    ),
                                    if("@element"->qv != "", "@element"->qv, "@element"->nv)
                                ),
                                replace(
                                    replace(
                                        arraystring(arraymap(split("@element", """\\\\"""), replace("@element", """\\""", "")), """\\"""),
                                        """\\""", """\\\\"""
                                    ),
                                    """\"""", """\\\""""
                                )
                            )
                        )
                    ),
                    if(
                        array_length("@element"->x[]) = 2,
                        format_string("\"%s\",\"%s\"", "@element"->x[0], "@element"->x[1]),
                        format_string("\"%s\"", "@element"->x[0])
                    )
                ),
                0
            )
        ),
        ":"
    )
)
;

[RULE: minoue_csv2array]
/***
 * This rule transforms a comma separated value to an array.
 * The standard pattern is:
 *    value[,value]*
 *
 *  e.g.
 *    val1,val2,val3
 *
 * ### Supported Syntax/Formats
 *  - A back-slash charator escapes a following charactor.
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
 * You should ensure the text in the correct format with $PATTERN_CSV in advance if needed.
 *
 * :param __text: A comma separated text
 * :return _columns: Array of column values
 *
 * @auther Masahiko Inoue
 * @url https://github.com/spearmin10/xsiam-utils/blob/main/parsing-rules/minoue-parsing-rules.xql
 ***/
alter _columns = arraymap(
    regextract(
        replace(to_string(coalesce(__text, "")), ",", ",,"),
        "(?:^|,)\s*(?:\"(?:\"\"|\\.|[^\"])*\"|(?:\\,,|\\[^,]|[^,\\])*)\s*(?:,|$)"
    ),
    arrayindex(
        arraymap(
            arraymap(
                arraycreate(
                    regexcapture(replace(to_string("@element"), ",,", ","), "^\s*,?\s*(?:\"(?P<qv>(?:\"\"|\\.|[^\"])*)\"|(?P<nv>(?:\\.|[^,])*?))\s*,?\s*$")
                ),
                if("@element"->qv != "", "@element"->qv, "@element"->nv)
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
;

[RULE: minoue_ssv2array]
/***
 * This rule transforms a space separated value to an array.
 * The standard pattern is:
 *    value[ value]*
 *
 *  e.g.
 *    val1 val2 val3
 *
 * 'value' can be quoted with a double quotation mark, and also a back-slash escapes a following charactor.
 *   e.g.
 *    - "value"
 *    - va\ lue
 *    - va\\lue
 *    - va\"lue
 *
 * :param __text: A space separated text
 * :return _columns: Array of column values
 *
 * @auther Masahiko Inoue
 * @url https://github.com/spearmin10/xsiam-utils/blob/main/parsing-rules/minoue-parsing-rules.xql
 ***/
alter _columns = arraymap(
    regextract(
        to_string(coalesce(__text, "")),
        "(?:\"(?:\\.|[^\\\"])*\"|(?:\\.|[^\\\s]))+\s+|(?:\"(?:\\.|[^\\\"])*\"|(?:\\.|[^\\\s]))+$"
    ),
    arrayindex(
        arraymap(
            arraycreate(
                regexcapture(trim(to_string("@element")), "^(?:\"(?P<qv>(?:\\.|[^\"])*)\"|(?P<nv>.*))$")
            ),
            if(
                "@element"->qv != "",
                arraystring(arraymap(split("@element"->qv, """\\\\"""), replace("@element", """\\""", "")), """\\"""),
                arraystring(arraymap(split("@element"->nv, """\\\\"""), replace("@element", """\\""", "")), """\\""")
            )
        ),
        0
    )
)
;

[RULE: minoue_syslog_lite]
/***
 * This rule extracts parameters from a syslog payload.
 * It supports both of RFC 3164 and 5424 log format.
 *
 * The parameters extracted are saved to 'syslog' in JSON object with the following structure.
 * However 'syslog' will be null if the log is not the correct format.
 * It doesn't support to parse SD-PARAM of STRUCTURED-DATA in the RFC 5424 log,
 * so 'syslog.structured_data.params' is always empty.
 *
 *  {
 *    "pri": {
 *      "_raw": <number>,
 *      "facility": {
 *        "_raw": <number>,
 *        "name": <string>
 *      },
 *      "severity": {
 *        "_raw": <number>,
 *        "name": <string>
 *      }
 *    },
 *    "version": <number> | <null>,
 *    "datetime": <string> | <null>,
 *    "timestamp": <TIMESTAMP | <null>,
 *    "host": <string> | <null>,
 *    "app": <string> | <null>,
 *    "proc_id": <string> | <null>,
 *    "msg_id": <string> | <null>,
 *    "tag": <string> | <null>,
 *    "pid": <number> | <null>,
 *    "structured_data": {
 *      "_raw": <string> | <null>,
 *      "id": <string> | <null>,
 *      "data": {
 *        "_raw": <string> | <null>,
 *        "params": {}
 *      }
 *    },
 *    "message": <string>
 *  }
 *
 * :param __log: The log to parse
 * :return syslog: Parameters extracted from the log in JSON object.
 *
 * @auther Masahiko Inoue
 * @url https://github.com/spearmin10/xsiam-utils/blob/main/parsing-rules/minoue-parsing-rules.xql
 ***/
// Parse syslog message
alter _x = regexcapture(__log, "^(<(?P<pri>\d{1,3})>)((?P<datetime_3164>(?P<mon>(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)) +(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2})) (?P<host_3164>\S+) ((?P<tag>[^:\[]{1,32})(\[(?P<pid>\d*)\])?: )?(?P<msg_3164>.*)|(?P<version>\d{1,2}) (-|(?P<datetime_5424>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(.\d{1,6})?(Z|[+-]\d{2}:\d{2}))) (-|(?P<host_5424>\S{1,255})) (-|(?P<app>\S{1,48})) (-|(?P<proc_id>\S{1,128})) (-|(?P<msg_id>\S{1,32})) (-|\[(?P<structured_data>(?P<sd_id>[^ =\]]+) (?P<sd_data>(?:[^\]\\]|\\.)*))\])( (?P<msg_5424>(.*)))?)")

// Build syslog parameters
| alter _syslog = if(
    _x->pri != null,
    object_create(
        "header", object_create(
            "pri", object_create(
                "_raw", to_number(_x->pri),
                "facility", arrayindex(
                    arraymap(
                        arraycreate(floor(divide(to_number(_x->pri), 8))),
                        object_create(
                            "_raw", "@element",
                            "name", coalesce(arrayindex(split("kern,user,mail,daemon,auth,syslog,lpr,news,uucp,cron,authpriv,ftp,ntp,audit,alert,clock,local0,local1,local2,local3,local4,local5,local6,local7", ","), "@element"), "unknown")
                        )
                    ),
                    0
                ),
                "severity", arrayindex(
                    arraymap(
                        arraycreate(floor(subtract(to_number(_x->pri), multiply(floor(divide(to_number(_x->pri), 8)), 8)))),
                        object_create(
                            "_raw", "@element",
                            "name", arrayindex(split("emergency,alert,critical,error,warning,notice,informational,debug", ","), "@element")
                        )
                    ),
                    0
                )
            ),
            "version", to_number(_x->version),
            "datetime", if(_x->datetime_5424 != "", _x->datetime_5424, if(_x->datetime_3164 != "", _x->datetime_3164)),
            "timestamp", if(
                _x->datetime_5424 = "",
                // time params - RFC 3164
                parse_timestamp(
                  "%Y %b %d %H:%M:%S",
                  format_string("%d %s", extract_time(current_time(), "YEAR"), _x->datetime_3164)
                ),
                // time params - RFC 5424
                parse_timestamp(
                  "%Y-%m-%dT%H:%M:%E*S%Z",
                  replace(_x->datetime_5424, "Z", "+00:00")
                )
            ),
            "host", if(_x->host_5424 != "", _x->host_5424, if(_x->host_3164 != "", _x->host_3164)),
            "app", if( _x->app != "", _x->app),
            "proc_id", if( _x->proc_id != "", _x->proc_id),
            "msg_id", if( _x->msg_id != "", _x->msg_id),
            "tag", if( _x->["tag"] != "", _x->["tag"]),
            "pid", to_number(_x->pid),
            "structured_data", object_create(
                "_raw", if( _x->structured_data != "", _x->structured_data),
                "id", if( _x->sd_id != "", _x->sd_id),
                "data", object_create(
                    "_raw", if( _x->sd_data != "", _x->sd_data),
                    "params", "{}"->{}
                )
            )
        ),
        "message", if(_x->msg_3164 = "", _x->msg_5424, _x->msg_3164)
    )
)
| fields -_x
;

[RULE: minoue_syslog]
/***
 * This rule extracts parameters from a syslog payload.
 * It supports both of RFC 3164 and 5424 log format.
 *
 * The parameters extracted are saved to 'syslog' in JSON object with the following structure.
 * However 'syslog' will be null if the log is not the correct format.
 *
 *  {
 *    "pri": {
 *      "_raw": <number>,
 *      "facility": {
 *        "_raw": <number>,
 *        "name": <string>
 *      },
 *      "severity": {
 *        "_raw": <number>,
 *        "name": <string>
 *      }
 *    },
 *    "version": <number> | <null>,
 *    "datetime": <string> | <null>,
 *    "timestamp": <TIMESTAMP | <null>,
 *    "host": <string> | <null>,
 *    "app": <string> | <null>,
 *    "proc_id": <string> | <null>,
 *    "msg_id": <string> | <null>,
 *    "tag": <string> | <null>,
 *    "pid": <number> | <null>,
 *    "structured_data": {
 *      "_raw": <string> | <null>,
 *      "id": <string> | <null>,
 *      "data": {
 *        "_raw": <string> | <null>,
 *        "params": {
 *          <param-key>: <param-value: string>
 *        }
 *      }
 *    },
 *    "message": <string>
 *  }
 *
 * :param __log: The log to parse
 * :return _syslog: Parameters extracted from the log in JSON object.
 *
 * @auther Masahiko Inoue
 * @url https://github.com/spearmin10/xsiam-utils/blob/main/parsing-rules/minoue-parsing-rules.xql
 ***/
// Parse syslog message
alter _x = regexcapture(__log, "^(<(?P<pri>\d{1,3})>)((?P<datetime_3164>(?P<mon>(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)) +(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2})) (?P<host_3164>\S+) ((?P<tag>[^:\[]{1,32})(\[(?P<pid>\d*)\])?: )?(?P<msg_3164>.*)|(?P<version>\d{1,2}) (-|(?P<datetime_5424>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(.\d{1,6})?(Z|[+-]\d{2}:\d{2}))) (-|(?P<host_5424>\S{1,255})) (-|(?P<app>\S{1,48})) (-|(?P<proc_id>\S{1,128})) (-|(?P<msg_id>\S{1,32})) (-|\[(?P<structured_data>(?P<sd_id>[^ =\]]+) (?P<sd_data>(?:[^\]\\]|\\.)*))\])( (?P<msg_5424>(.*)))?)")
| alter __kvtext = _x->sd_data
| call minoue_sskv2kvobj

// Build syslog parameters
| alter _syslog = if(
    _x->pri != null,
    object_create(
        "header", object_create(
            "pri", object_create(
                "_raw", to_number(_x->pri),
                "facility", arrayindex(
                    arraymap(
                        arraycreate(floor(divide(to_number(_x->pri), 8))),
                        object_create(
                            "_raw", "@element",
                            "name", coalesce(arrayindex(split("kern,user,mail,daemon,auth,syslog,lpr,news,uucp,cron,authpriv,ftp,ntp,audit,alert,clock,local0,local1,local2,local3,local4,local5,local6,local7", ","), "@element"), "unknown")
                        )
                    ),
                    0
                ),
                "severity", arrayindex(
                    arraymap(
                        arraycreate(floor(subtract(to_number(_x->pri), multiply(floor(divide(to_number(_x->pri), 8)), 8)))),
                        object_create(
                            "_raw", "@element",
                            "name", arrayindex(split("emergency,alert,critical,error,warning,notice,informational,debug", ","), "@element")
                        )
                    ),
                    0
                )
            ),
            "version", to_number(_x->version),
            "datetime", if(_x->datetime_5424 != "", _x->datetime_5424, if(_x->datetime_3164 != "", _x->datetime_3164)),
            "timestamp", if(
                _x->datetime_5424 = "",
                // time params - RFC 3164
                parse_timestamp(
                  "%Y %b %d %H:%M:%S",
                  format_string("%d %s", extract_time(current_time(), "YEAR"), _x->datetime_3164)
                ),
                // time params - RFC 5424
                parse_timestamp(
                  "%Y-%m-%dT%H:%M:%E*S%Z",
                  replace(_x->datetime_5424, "Z", "+00:00")
                )
            ),
            "host", if(_x->host_5424 != "", _x->host_5424, if(_x->host_3164 != "", _x->host_3164)),
            "app", if( _x->app != "", _x->app),
            "proc_id", if( _x->proc_id != "", _x->proc_id),
            "msg_id", if( _x->msg_id != "", _x->msg_id),
            "tag", if( _x->["tag"] != "", _x->["tag"]),
            "pid", to_number(_x->pid),
            "structured_data", object_create(
                "_raw", if( _x->structured_data != "", _x->structured_data),
                "id", if( _x->sd_id != "", _x->sd_id),
                "data", object_create(
                    "_raw", if( _x->sd_data != "", _x->sd_data),
                    "params", _raw_kvobj -> {}
                )
            )
        ),
        "message", if(_x->msg_3164 = "", _x->msg_5424, _x->msg_3164)
    )
)
| fields -_x, __kvtext, _raw_kvobj
;
/* ******* END OF MINOUE Parsing Rules Library **********
 * ******************************************************/
