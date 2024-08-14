/* *******************************************************
 * MINOUE Parsing Rules Library
 *
 * @auther Masahiko Inoue
 * @url https://github.com/spearmin10/xsiam-utils/blob/main/parsing-rules/minoue-parsing-rules.xql
 * ******************************************************/
[CONST]
PATTERN_CSV = "^(\"(\\.|[^\"])*\"|(\\.|[^,=\"\s])+)\s*?=\s*?(\"(\\.|[^\"])*\"|(\\.|[^,\"\s])*)(,\s*(\"(\\.|[^\"])*\"|(\\.|[^,=\"\s])+)\s*=\s*(\"(\\.|[^\"])*\"|(\\.|[^,\"\s])*))*$";
PATTERN_SSV = "^(\"(\\.|[^\"])*\"|(\\.|[^=\"\s])+)\s*?=\s*?(\"(\\.|[^\"])*\"|(\\.|[^\"\s])*)(\s\s*(\"(\\.|[^\"])*\"|(\\.|[^=\"\s])+)\s*=\s*(\"(\\.|[^\"])*\"|(\\.|[^\"\s])*))*$";

[RULE: minoue_csv2kvobj]
/***
 * This rule transforms a csv (comma separated value) text to a json object.
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
 * You should ensure the text in the correct format with PATTERN_CSV in advance.
 * On the contrary, it will successfully return a JSON object without raising errors even if the text contains incorrect patterns.
 * You can give any texts if you want. It recommends to use `_raw_kvobj->{}` to get the entire JSON object in order to check if the return value is in the correct JSON object in case of incorrect text to be returned.
 *
 * :param __kvtext: A comma separated text
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
                "(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^,=\"\s])+)\s*?=\s*?(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^,\s])*)"
            ),
            arrayindex(
                arraymap(
                    arraycreate(
                        regexcapture(to_string("@element"), "^\"?(?P<key>.*?)\"?\s*?=\s*?\"?(?P<val>.*?)\"?$")
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
                                        replace(arraystring(arraymap(split("@element", """\\\\"""), replace("@element", """\\""", "")), """\\"""), """\\\\""", """\\"""),
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

[RULE: minoue_ssv2kvobj]
/***
 * This rule transforms a spaces separated value text to a json object.
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
 * You should ensure the text in the correct format with PATTERN_SSV.
  * On the contrary, it will successfully return a JSON object without raising errors even if the text contains incorrect patterns.
 * You can give any texts if you want. It recommends to use `_raw_kvobj->{}` to get the entire JSON object in order to check if the return value is in the correct JSON object in case of incorrect text to be returned.
 *
 * :param __kvtext: A comma separated text
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
                "(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^=\"\s])+)\s*?=\s*?(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^\s])*)"
            ),
            arrayindex(
                arraymap(
                    arraycreate(
                        regexcapture(to_string("@element"), "^\"?(?P<key>.*?)\"?\s*?=\s*?\"?(?P<val>.*?)\"?$")
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
                                        replace(arraystring(arraymap(split("@element", """\\\\"""), replace("@element", """\\""", "")), """\\"""), """\\\\""", """\\"""),
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

[RULE: minoue_nqssv2kvobj]
/***
 * This rule transforms a spaces separated value text to a json object.
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
 *  - 'key' can contain any spaces only when it's quoted or a space in it is escaped.
 *  - 'key' and 'value' between '=' allows any spaces to be inserted.
 *  - 'key' of the next key=value can be placed immediately after the current key=value without any spaces when at least one of the current 'value' or the next 'key' is quoted.
 * 
 *   e.g.
 *    - key1="val1" key2="val2"
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
 *
 * You will get unexpected results if you give a text in incorrect patterns as it doesn't check it.
 * It's responsible for you to ensure the text in the correct format before giving it,
 * however you wouldn't be able to check the pattern only with RE2.
 * You can give any texts if you want. It recommends to use `_raw_kvobj->{}` to get the entire JSON object in order to check if the return value is in the correct JSON object in case of incorrect text to be returned.
 *
 * :param __kvtext: A comma separated text (__kvtext is modified in the process)
 * :return _raw_kvobj: JSON object text
 *
 * @auther Masahiko Inoue
 * @url https://github.com/spearmin10/xsiam-utils/blob/main/parsing-rules/minoue-parsing-rules.xql
 ***/
alter __kvtext = arraystring(
    arraymap(
        regextract(
            replace(to_string(coalesce(__kvtext, "")), "=", "=="),
            "=(?:\\==|\\[^=]|[^=\\])+?=|^(?:\\==|\\[^=]|[^=\\])+?=|=(?:\\==|\\[^=]|[^=\\])*?$"
        ),
        arraystring(
            arraymap(
                arraycreate(
                    // val + key
                    regexcapture(to_string("@element"), "^=\s*(?P<v>\"(?:\\==|\\[^=]|[^\\\"])*\"|(?:(?:\\==|\\[^=]|[^\\\"=])+?))\s*(?P<k>\"(?:\\==|\\[^=]|[^\\\"])*\"|(?:(?:\\==|\\[^=]|[^\\\"=\s])+))\s*=$"),

                    // first key
                    regexcapture(to_string("@element"), "^\s*(?P<k>\"(?:\\.|[^\\\"])*\"|(?:(?:\\==|\\[^=]|[^\\\"=\s])+))\s*=$"),

                    // last value
                    regexcapture(to_string("@element"), "^=\s*(?P<v>\"(?:\\==|\\[^=]|[^\\\"])*\"|(?:(?:\\==|\\[^=]|[^\\\"=])*?))\s*$")
                ),
                arraystring(
                    arraymap(
                        arraymap(
                            arrayconcat(
                                if(
                                    "@element"->v != null and "@element"->v != "",
                                    regextract("@element"->v, "^\"?(.*?)\"?$"),
                                    "[]"->[]
                                ),
                                if(
                                    "@element"->k != null and "@element"->k != "",
                                    regextract("@element"->k, "^\"?(.*?)\"?$"),
                                    "[]"->[]
                                )
                            ),
                            replace("@element", "\==", "=")
                        ),
                        format_string(
                            "\"%s\"",
                            // Escape backsrashs and double quotations
                            replace(
                                replace(
                                    // Unescape escaped charactors
                                    replace(arraystring(arraymap(split("@element", """\\\\"""), replace("@element", """\\""", "")), """\\"""), """\\\\""", """\\"""),
                                    """\\""", """\\\\"""
                                ),
                                """\"""", """\\\""""
                            )
                        )
                    ),
                    ""
                )
            ),
            ""
        )
    ),
    "="
)
| call minoue_ssv2kvobj
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
| alter _facility = floor(divide(to_number(_x->pri), 8))
| alter _severity = floor(subtract(to_number(_x->pri), multiply(floor(divide(to_number(_x->pri), 8)), 8)))

// Build syslog parameters
| alter syslog = if(
    _x->pri != null,
    object_create(
        "header", object_create(
            "pri", object_create(
                "_raw", to_number(_x->pri),
                "facility", object_create(
                    "_raw", _facility,
                    "name", coalesce(arrayindex(split("kern,user,mail,daemon,auth,syslog,lpr,news,uucp,cron,authpriv,ftp,ntp,audit,alert,clock,local0,local1,local2,local3,local4,local5,local6,local7", ","), _facility), "unknown")
                ),
                "severity", object_create(
                    "_raw", _severity,
                    "name", arrayindex(split("emergency,alert,critical,error,warning,notice,informational,debug", ","), _severity)
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
                "data", object_create()
            )
        ),
        "message", if(_x->msg_3164 = "", _x->msg_5424, _x->msg_3164)
    )
)
| fields -_x, _facility, _severity
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
 * :return syslog: Parameters extracted from the log in JSON object.
 *
 * @auther Masahiko Inoue
 * @url https://github.com/spearmin10/xsiam-utils/blob/main/parsing-rules/minoue-parsing-rules.xql
 ***/
// Parse syslog message
alter _x = regexcapture(__log, "^(<(?P<pri>\d{1,3})>)((?P<datetime_3164>(?P<mon>(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)) +(?P<day>\d{1,2}) (?P<time>\d{2}:\d{2}:\d{2})) (?P<host_3164>\S+) ((?P<tag>[^:\[]{1,32})(\[(?P<pid>\d*)\])?: )?(?P<msg_3164>.*)|(?P<version>\d{1,2}) (-|(?P<datetime_5424>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(.\d{1,6})?(Z|[+-]\d{2}:\d{2}))) (-|(?P<host_5424>\S{1,255})) (-|(?P<app>\S{1,48})) (-|(?P<proc_id>\S{1,128})) (-|(?P<msg_id>\S{1,32})) (-|\[(?P<structured_data>(?P<sd_id>[^ =\]]+) (?P<sd_data>(?:[^\]\\]|\\.)*))\])( (?P<msg_5424>(.*)))?)")
| alter _facility = floor(divide(to_number(_x->pri), 8))
| alter _severity = floor(subtract(to_number(_x->pri), multiply(floor(divide(to_number(_x->pri), 8)), 8)))
| alter __kvtext = _x->sd_data
| call minoue_ssv2kvobj

// Build syslog parameters
| alter syslog = if(
    _x->pri != null,
    object_create(
        "header", object_create(
            "pri", object_create(
                "_raw", to_number(_x->pri),
                "facility", object_create(
                    "_raw", _facility,
                    "name", coalesce(arrayindex(split("kern,user,mail,daemon,auth,syslog,lpr,news,uucp,cron,authpriv,ftp,ntp,audit,alert,clock,local0,local1,local2,local3,local4,local5,local6,local7", ","), _facility), "unknown")
                ),
                "severity", object_create(
                    "_raw", _severity,
                    "name", arrayindex(split("emergency,alert,critical,error,warning,notice,informational,debug", ","), _severity)
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
| fields -_x, _facility, _severity, __kvtext, _raw_kvobj
;
/* ******* END OF MINOUE Parsing Rules Library **********
 * ******************************************************/