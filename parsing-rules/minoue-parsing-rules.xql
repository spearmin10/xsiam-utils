/* *******************************************************
 * MINOUE Parsing Rules Library
 *
 * @auther Masahiko Inoue
 * @url https://github.com/spearmin10/xsiam-utils/blob/main/parsing-rules/minoue-parsing-rules.xql
 * ******************************************************/
[CONST]
PATTERN_CSKV = "^(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^,=\"\s])+)\s*?=\s*?(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^,\"])*)(?:,\s*(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^,=\"\s])+)\s*=\s*(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^,\"])*))*$";
PATTERN_SSKV = "^(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^=\"\s])+)\s*?=\s*?(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^\"\s])*)(?:\s\s*(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^=\"\s])+)\s*=\s*(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^\"\s])*))*$";
PATTERN_CSV = "^\s*(?:(?:\"(?:\"\"|\\.|[^\\\"])*\")|[^,\"]*?)\s*(?:,\s*(?:(?:\"(?:\"\"|\\.|[^\\\"])*\")|[^,\"]*?)\s*)*$";
PATTERN_IPV4 = "^(?:(?:25[0-5]|(?:2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$";

[RULE: minoue_skv2kvobj]
/***
 * This rule transforms a separated key-value text into a JSON object.
 * Any single character can be used as a separator, except for the backslash (`\`) and the double quotation mark (`"`).
 * The standard pattern is:
 *    key<kv-separator>value[<ent-separator> key<kv-separator>value]*
 *
 *   e.g.
 *    key1=val1, key2=val2, key3=val3
 *    key1:val1; key2:val2; key3:val3
 *
 * ### Supported Syntax/Formats  
 *  - The key-value separator (`<kv-separator>`) must be a single character.
 *  - The entry separator (`<ent-separator>`) must also be a single character.
 *  - The key-value separator and the entry separator must be different characters.
 *  - 'key' and 'value' can be enclosed in double quotation marks.
 *  - Spaces are allowed around the key-value separator between the 'key' and 'value'.
 *  - 'value' can contain any number of spaces.
 *  - A backslash (`\`) escapes the following character in quoted text.
 *  - Spaces are allowed between the value and the key-value separator.
 *  - The following escape sequences are interpreted as control characters:
 *      * `\b` : backspace
 *      * `\f` : form feed
 *      * `\n` : line feed
 *      * `\r` : carriage return
 *      * `\t` : tab
 *
 *   e.g.
 *    - "key":"value"
 *    - key : value
 *    - key : "value"
 *    - "k\"ey" : "va\\lue"
 *    - key1:v a l 1; key2: v a l 2
 *
 * It also supports text separated using any entry separator, or even without an entry separator,
 * as long as each `value` is enclosed in double quotation marks.
 *
 *   e.g.
 *    - key1:"v a l 1" key2:"v a l 2"; key3:val3
 *    - key1:"v a l 1"key2:"v a l 2"
 *    - key1:"v a l 1""key2":"v a l 2"
 *
 * You may get unexpected results if the input text contains incorrect patterns, as the parser does not perform validation.
 * It is your responsibility to ensure that the text follows the correct format.
 * That said, the parser will still return a JSON object without raising errors, even if the text is improperly formatted.
 * You can input any text, but it's recommended to use `_raw_kvobj->{}` to retrieve the full JSON object and verify its correctness,
 * especially when dealing with potentially invalid input.
 *
 * :param __kvtext: A string of separated key-value pairs
 * :param __ent_separator: The character used to separate entries
 * :param __kv_separator: The character used to separate keys and values
 * :return _raw_kvobj: A JSON object generated from the key-value text
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
                replace(
                    replace(
                        "(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^,=\"\s])+)\s*?=\s*(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^,])*)",
                        "=",
                        __kv_separator
                    ),
                    ",",
                    __ent_separator
                )
            ),
            arrayindex(
                arraymap(
                    arraycreate(
                        regexcapture(
                            to_string("@element"),
                            replace("^\"?(?P<key>(?:\\.|[^\\\"])*?)\"?\s*?=\s*\"?(?P<val>.*?)\"?$", "=", __kv_separator)
                        )
                    ),
                    format_string(
                        "\"%s\"",
                        arraystring(
                            arraymap(
                                arraycreate(lowercase("@element"->key), "@element"->val),
                                // Encode to JSON string
                                replace(replace(replace(replace(replace(replace(replace(replace(
                                    arraystring(
                                        arraymap(
                                            split("@element", """\\\\"""),
                                            replace(replace(replace(replace(replace(replace("@element",
                                                "\n", convert_from_base_64("Cg==")),
                                                "\r", convert_from_base_64("DQ==")),
                                                "\t", convert_from_base_64("CQ==")),
                                                "\b", convert_from_base_64("CA==")),
                                                "\f", convert_from_base_64("DA==")),
                                                """\\""", ""
                                            )
                                        ),
                                        """\\"""
                                    ),
                                    convert_from_base_64("Cg=="), "\n"),
                                    convert_from_base_64("DQ=="), "\r"),
                                    convert_from_base_64("CQ=="), "\t"),
                                    convert_from_base_64("CA=="), "\b"),
                                    convert_from_base_64("DA=="), "\f"),
                                    """\\""", """\\\\"""),
                                    """\"""", """\\\""""),
                                    "/", """\\/"""
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

[RULE: minoue_cskv2kvobj]
/***
 * This rule transforms a comma-separated key=value text into a JSON object.
 * The standard pattern is:
 *    key=value[, key=value]*
 *
 *   e.g.
 *    - key1=val1, key2=val2, key3=val3
 *
 * ### Supported Syntax/Formats
 *  - Both 'key' and 'value' can be enclosed in double quotation marks.  
 *  - Spaces are allowed around the '=' between 'key' and 'value'.  
 *  - The `value` can contain any number of spaces.  
 *  - A backslash escapes the following character in quoted text.  
 *  - Spaces are allowed between a value and the comma separator.  
 *  - The following escape sequences are interpreted as control characters:  
 *      * \b : backspace  
 *      * \f : form feed  
 *      * \n : line feed  
 *      * \r : carriage return  
 *      * \t : tab
 *
 *   e.g.
 *    - "key"="value"
 *    - key = value
 *    - key = "value"
 *    - "k\"ey" = "va\\lue"
 *    - key1=v a l 1, key2= v a l 2
 *
 *  It also supports text separated by any delimiters, or without a delimiter, if the `value` is enclosed in double quotation marks.
 *  However, $PATTERN_CSKV does not match the text because it is not a comma-separated key-value pair.
 *
 *   e.g.
 *    - key1="v a l 1" key2="v a l 2", key3=val3
 *    - key1="v a l 1"key2="v a l 2"
 *    - key1="v a l 1""key2"="v a l 2"
 *
 * You may get unexpected results if you provide text containing incorrect patterns, as it does not perform validation.
 * You should ensure that the text is in the correct format using $PATTERN_CSKV beforehand.
 * That said, it will still successfully return a JSON object without raising errors, even if the text contains incorrect patterns.
 * You can provide any text you like. However, it is recommended to use `_raw_kvobj->{}` to retrieve the full JSON object and
 * verify its correctness, especially if the text may be incorrectly formatted.
 *
 * :param __kvtext: A comma-separated key=value text  
 * :return _raw_kvobj: A JSON object generated from the key=value text
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
                "(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^,=\"\s])+)\s*?=\s*(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^,])*)"
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
                                // Encode to JSON string
                                replace(replace(replace(replace(replace(replace(replace(replace(
                                    arraystring(
                                        arraymap(
                                            split("@element", """\\\\"""),
                                            replace(replace(replace(replace(replace(replace("@element",
                                                "\n", convert_from_base_64("Cg==")),
                                                "\r", convert_from_base_64("DQ==")),
                                                "\t", convert_from_base_64("CQ==")),
                                                "\b", convert_from_base_64("CA==")),
                                                "\f", convert_from_base_64("DA==")),
                                                """\\""", ""
                                            )
                                        ),
                                        """\\"""
                                    ),
                                    convert_from_base_64("Cg=="), "\n"),
                                    convert_from_base_64("DQ=="), "\r"),
                                    convert_from_base_64("CQ=="), "\t"),
                                    convert_from_base_64("CA=="), "\b"),
                                    convert_from_base_64("DA=="), "\f"),
                                    """\\""", """\\\\"""),
                                    """\"""", """\\\""""),
                                    "/", """\\/"""
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
 * This rule transforms a space-separated key=value text into a JSON object.
 * The standard pattern is:
 *    key=value[ key=value]*
 *
 *  e.g.
 *    - key1=val1 key2=val2 key3=val3
 *
 * 'key' and 'value' can be enclosed in double quotation marks. Spaces are allowed around the '=' between 'key' and 'value',
 * and a backslash escapes the following character in quoted text.
 *
 *   e.g.
 *    - "key"="value"
 *    - key = value
 *    - key = "value"
 *    - "k\"ey" = "va\\lue"
 *
 * If the `value` is enclosed in double quotation marks, the text can be separated by any delimiters or even have no delimiter.
 *
 *   e.g.
 *    - key1="v a l 1" key2="v a l 2", key3=val3
 *    - key1="v a l 1"key2="v a l 2"
 *    - key1="v a l 1",key2="v a l 2"
 *    - key1="v a l 1""key2"="v a l 2"
 *    - key1="v a l 1","key2"="v a l 2"
 *
 * The following escape sequences are interpreted as control characters.
 *
 *  - \b : backspace
 *  - \f : form feed
 *  - \n : line feed
 *  - \r : carriage return
 *  - \t : tab
 *
 * You may get unexpected results if you provide text with incorrect patterns, as it does not perform validation.  
 * You should ensure the text is in the correct format using $PATTERN_SSKV.  
 * That said, it will still return a JSON object without raising errors, even if the text contains incorrect patterns.  
 * You can provide any text you like. However, it is recommended to use `_raw_kvobj->{}` to retrieve the entire JSON object and
 * verify its correctness, especially when the text may be incorrectly formatted.  
 *  
 * :param __kvtext: A space-separated key=value text  
 * :return _raw_kvobj: A JSON object generated from the key=value text
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
                                // Encode to JSON string
                                replace(replace(replace(replace(replace(replace(replace(replace(
                                    arraystring(
                                        arraymap(
                                            split("@element", """\\\\"""),
                                            replace(replace(replace(replace(replace(replace("@element",
                                                "\n", convert_from_base_64("Cg==")),
                                                "\r", convert_from_base_64("DQ==")),
                                                "\t", convert_from_base_64("CQ==")),
                                                "\b", convert_from_base_64("CA==")),
                                                "\f", convert_from_base_64("DA==")),
                                                """\\""", ""
                                            )
                                        ),
                                        """\\"""
                                    ),
                                    convert_from_base_64("Cg=="), "\n"),
                                    convert_from_base_64("DQ=="), "\r"),
                                    convert_from_base_64("CQ=="), "\t"),
                                    convert_from_base_64("CA=="), "\b"),
                                    convert_from_base_64("DA=="), "\f"),
                                    """\\""", """\\\\"""),
                                    """\"""", """\\\""""),
                                    "/", """\\/"""
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

[RULE: minoue_xnqskv2kvobj]
/***
 * This rule transforms a separated key-value text into a JSON object.
 * Any character can be used as a separator, except for the backslash and double quotation mark.
 * The standard pattern is:
 *    key<kv-separator>value[<ent-separator> key<kv-separator>value]*
 *
 *  e.g.
 *    key1=val1, key2=val2, key3=val3
 *    key1:val1; key2:val2; key3:val3
 *
 * ### Supported Syntax/Formats
 *  - The Key-Value separator (<kv-separator>) must be a single character (length=1).
 *  - The entry separator (<ent-separator>) must be a single character (length=1).
 *  - The Key-Value separator and the entry separator must be different characters.
 *  - Neither the Key-Value separator nor the entry separator can be a backslash or a double quotation mark.
 *  - A backslash escapes the following character in quoted text.
 *  - Spaces are allowed between a value and a comma separator.
 *  - 'key' and 'value' can be enclosed in double quotation marks.
 *  - Spaces are allowed between 'key' and 'value' around the <kv-separator>.
 *  - 'value' can contain spaces, whether quoted or not.
 *  - 'value' can contain multiple tokens enclosed in double quotation marks.
 *  - 'value' can be empty, whether quoted or not.
 *  - 'key' can contain spaces only if it is quoted or if the spaces are escaped.
 *  - The 'key' of the next key-value pair can immediately follow the current pair without a comma, as long as at least one of the current 'value' or the next 'key' is quoted.
 *  - Key-value pairs can be delimited by spaces when at least one of the current 'value' or the next 'key' is quoted.
 *  - The following escape sequences are interpreted as control characters:
 *      * \b : backspace
 *      * \f : form feed
 *      * \n : line feed
 *      * \r : carriage return
 *      * \t : tab
 *
 *   e.g.
 *    - "key":"value"
 *    - key : value
 *    - key : "value"
 *    - "k\"ey" : "va\\lue"
 *    - key1:val\:1; key2:val2
 *    - key1:v a l 1; key2: v a l 2
 *    - key1:"v1[1]" v1[2] "v1[3]"; key2=v2[1] "v2[2]"
 *    - key1 : ;key2 : ""
 *    - "k e y 1" : val1; key\ 2 : val2
 *    - "k e y 1" : "v a l 1"key2 : "v a l 2"
 *    - "key1":"val1" "key2":"val2"
 *
 * You may get unexpected results if you provide text with incorrect patterns, as it does not perform validation.
 * It is your responsibility to ensure that the text is in the correct format before providing it.
 * However, you will not be able to validate the pattern using only RE2.
 * You can provide any text you like, but it is recommended to use `_raw_kvobj->{}` to retrieve the entire JSON object and
 * verify its correctness, especially if the text is incorrectly formatted.
 *
 * :param __kvtext: A separated key-value text
 * :param __ent_separator: An entry separator
 * :param __kv_separator: A key-value separator
 * :return _raw_kvobj: A JSON object generated from the key-value text
 *
 * @auther Masahiko Inoue
 * @url https://github.com/spearmin10/xsiam-utils/blob/main/parsing-rules/minoue-parsing-rules.xql
 ***/
alter _raw_kvobj = format_string(
    "{%s}",
    arraystring(
        arraymap(
            regextract(
                replace(to_string(coalesce(__kvtext, "")), __kv_separator, concat(__kv_separator, __kv_separator)),
                replace(
                    "=(?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=\"]|[^=\\\"]))+?=|^(?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=\"]|[^=\\\"]))*?=|=(?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=\"]|[^=\\\"]))*?$",
                    "=",
                    __kv_separator
                )
            ),
            arrayindex(
                arraymap(
                    arraymap(
                        arraycreate(
                            regexcapture(
                                to_string("@element"),
                                replace(
                                    replace(
                                        "^(?:=\s*(?P<vkv>(?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=]|[^\\\"=]))*?)\s*?,\s*(?P<vkk>\"(?:\\.|[^\\\"])*\"|(?:(?:\\==|\\[^=]|[^\\\"=\s])+))\s*=|\s*(?P<fk>\"(?:\\.|[^\\\"])*\"|(?:(?:\\==|\\[^=]|[^\\\"=])+))\s*=|=\s*(?P<lv>(?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=]|[^\\\"=]))*?)\s*)$",
                                        "=",
                                        __kv_separator
                                    ),
                                    ",",
                                    __ent_separator
                                )
                            )
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
                                        regexcapture(
                                            replace("@element", concat(__kv_separator, __kv_separator), __kv_separator),
                                            "^(?:\"(?P<qv>(?:\\.|[^\"])*)\"|(?P<nv>.*))$"
                                        )
                                    ),
                                    if("@element"->qv != "", "@element"->qv, "@element"->nv)
                                ),
                                // Encode to JSON string
                                replace(replace(replace(replace(replace(replace(replace(replace(
                                    arraystring(
                                        arraymap(
                                            split("@element", """\\\\"""),
                                            replace(replace(replace(replace(replace(replace("@element",
                                                "\n", convert_from_base_64("Cg==")),
                                                "\r", convert_from_base_64("DQ==")),
                                                "\t", convert_from_base_64("CQ==")),
                                                "\b", convert_from_base_64("CA==")),
                                                "\f", convert_from_base_64("DA==")),
                                                """\\""", ""
                                            )
                                        ),
                                        """\\"""
                                    ),
                                    convert_from_base_64("Cg=="), "\n"),
                                    convert_from_base_64("DQ=="), "\r"),
                                    convert_from_base_64("CQ=="), "\t"),
                                    convert_from_base_64("CA=="), "\b"),
                                    convert_from_base_64("DA=="), "\f"),
                                    """\\""", """\\\\"""),
                                    """\"""", """\\\""""),
                                    "/", """\\/"""
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

[RULE: minoue_nqsskv2kvobj]
/***
 * This rule transforms a space-separated key=value text into a JSON object.
 * The standard pattern is:
 *    key=value[ key=value]*
 *
 *  e.g.
 *    key1=val1 key2=val2 key3=val3
 *
 * ### Supported Syntax/Formats
 *  - A backslash character escapes the following character.
 *  - 'value' can contain spaces.
 *  - The 'value' starts immediately after the '=' sign that separates the key and value.
 *  - All spaces, except for the last one, are treated as trailing spaces in the value of the key.
 *  - 'key' can contain spaces only if they are escaped.
 *  - Trailing spaces between a key and the '=' sign are ignored.
 *  - The following escape sequences are interpreted as control characters:
 *      * \b : backspace
 *      * \f : form feed
 *      * \n : line feed
 *      * \r : carriage return
 *      * \t : tab
 *
 *   e.g.
 *    - key1=val1 key2=val2
 *    - key1=val\=1 key2=val\=2
 *    - key1=v a l 1 key2=v a l 2
 *    - key1=val\=1 key2=val\=2
 *    - key1= key2= key3=
 *
 * You may get unexpected results if you provide text with incorrect patterns, as it does not perform validation.
 * It is your responsibility to ensure the text is in the correct format before providing it.
 * However, you will not be able to validate the pattern using only RE2.
 * You can provide any text you like, but it is recommended to use `_raw_kvobj->{}` to retrieve the entire JSON object and
 * verify its correctness, especially if the text is incorrectly formatted.
 *
 * :param __kvtext: A space-separated key=value text
 * :return _raw_kvobj: A JSON object generated from the key=value text
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
                "=(?:\\==|\\[^=]|[^=\\])+?=|^(?:\\==|\\[^=]|[^=\\])*?=|=(?:\\==|\\[^=]|[^=\\])*?$"
            ),
            arrayindex(
                arraymap(
                    arraymap(
                        arraycreate(
                            regexcapture(to_string("@element"), "^(?:=(?P<vkv>(?:\\==|\\[^=]|[^\\=])*?)\s?(?P<vkk>(?:\\==|\\[^=]|[^\\=\s])+?)\s*=|\s*(?P<fk>(?:\\==|\\[^=]|[^\\=])+?)\s*=|=(?P<lv>(?:\\==|\\[^=]|[^\\=])*?))$")
                        ),
                        object_create(
                            "x",
                            arraymap(
                                arraymap(
                                    if(
                                        "@element"->vkk != "",
                                        arraycreate("@element"->vkv, "@element"->vkk),
                                        if("@element"->fk != "", arraycreate("@element"->fk), arraycreate("@element"->lv))
                                    ),
                                    replace("@element", "==", "=")
                                ),
                                // Encode to JSON string
                                replace(replace(replace(replace(replace(replace(replace(replace(
                                    arraystring(
                                        arraymap(
                                            split("@element", """\\\\"""),
                                            replace(replace(replace(replace(replace(replace("@element",
                                                "\n", convert_from_base_64("Cg==")),
                                                "\r", convert_from_base_64("DQ==")),
                                                "\t", convert_from_base_64("CQ==")),
                                                "\b", convert_from_base_64("CA==")),
                                                "\f", convert_from_base_64("DA==")),
                                                """\\""", ""
                                            )
                                        ),
                                        """\\"""
                                    ),
                                    convert_from_base_64("Cg=="), "\n"),
                                    convert_from_base_64("DQ=="), "\r"),
                                    convert_from_base_64("CQ=="), "\t"),
                                    convert_from_base_64("CA=="), "\b"),
                                    convert_from_base_64("DA=="), "\f"),
                                    """\\""", """\\\\"""),
                                    """\"""", """\\\""""),
                                    "/", """\\/"""
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

[RULE: minoue_xnqcskv2kvobj]
/***
 * This rule transforms a comma-separated key=value text into a JSON object.
 * The standard pattern is:
 *    key=value[, key=value]*
 *
 *  e.g.
 *    key1=val1, key2=val2, key3=val3
 *
 * ### Supported Syntax/Formats
 *  - A backslash escapes the following character in quoted text.
 *  - Any spaces can be allowed between a value and a comma separator.
 *  - 'key' and 'value' can be enclosed in double quotation marks.
 *  - Any spaces can be inserted between 'key' and 'value' around the '=' separator.
 *  - 'value' can contain spaces, whether quoted or not.
 *  - 'value' can contain multiple tokens enclosed in double quotation marks.
 *  - 'value' can be empty, whether quoted or not.
 *  - 'key' can contain spaces only if it is quoted or if the spaces are escaped.
 *  - The 'key' of the next key=value pair can follow immediately after the current key=value pair without a comma, as long as at least one of the current 'value' or the next 'key' is quoted.
 *  - Key=value pairs can be delimited by spaces when at least one of the current 'value' or the next 'key' is quoted.
 *  - The following escape sequences are interpreted as control characters:
 *      * \b : backspace  
 *      * \f : form feed  
 *      * \n : line feed  
 *      * \r : carriage return  
 *      * \t : tab
 *
 *   e.g.
 *    - "key"="value"
 *    - key = value
 *    - key = "value"
 *    - "k\"ey" = "va\\lue"
 *    - key1=val\,1, key2=val2
 *    - key1=v a l 1, key2= v a l 2
 *    - key1="v1[1]" v1[2] "v1[3]", key2=v2[1] "v2[2]"
 *    - key1 = ,key2 = ""
 *    - "k e y 1" = val1, key\ 2 = val2
 *    - "k e y 1" = "v a l 1"key2 = "v a l 2"
 *    - "key1"="val1" "key2"="val2"
 *
 * You may get unexpected results if you provide text with incorrect patterns, as it does not perform validation.
 * It is your responsibility to ensure the text is in the correct format before providing it.
 * However, you will not be able to validate the pattern using only RE2.
 * You can provide any text you like. It is recommended to use `_raw_kvobj->{}` to retrieve the entire JSON object and
 * verify its correctness, especially if the text is incorrectly formatted.
 *
 * :param __kvtext: A space-separated key=value text
 * :return _raw_kvobj: A JSON object generated from the key=value text
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
                "=(?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=\"]|[^=\\\"]))+?=|^(?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=\"]|[^=\\\"]))*?=|=(?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=\"]|[^=\\\"]))*?$"
            ),
            arrayindex(
                arraymap(
                    arraymap(
                        arraycreate(
                            regexcapture(to_string("@element"), "^(?:=\s*(?P<vkv>(?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=]|[^\\\"=]))*?)\s*?,\s*(?P<vkk>\"(?:\\.|[^\\\"])*\"|(?:(?:\\==|\\[^=]|[^\\\"=\s])+))\s*=|\s*(?P<fk>\"(?:\\.|[^\\\"])*\"|(?:(?:\\==|\\[^=]|[^\\\"=])+))\s*=|=\s*(?P<lv>(?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=]|[^\\\"=]))*?)\s*)$")
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
                                // Encode to JSON string
                                replace(replace(replace(replace(replace(replace(replace(replace(
                                    arraystring(
                                        arraymap(
                                            split("@element", """\\\\"""),
                                            replace(replace(replace(replace(replace(replace("@element",
                                                "\n", convert_from_base_64("Cg==")),
                                                "\r", convert_from_base_64("DQ==")),
                                                "\t", convert_from_base_64("CQ==")),
                                                "\b", convert_from_base_64("CA==")),
                                                "\f", convert_from_base_64("DA==")),
                                                """\\""", ""
                                            )
                                        ),
                                        """\\"""
                                    ),
                                    convert_from_base_64("Cg=="), "\n"),
                                    convert_from_base_64("DQ=="), "\r"),
                                    convert_from_base_64("CQ=="), "\t"),
                                    convert_from_base_64("CA=="), "\b"),
                                    convert_from_base_64("DA=="), "\f"),
                                    """\\""", """\\\\"""),
                                    """\"""", """\\\""""),
                                    "/", """\\/"""
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

[RULE: minoue_xnqsskv2kvobj]
/***
 * This rule transforms a space-separated key=value text into a JSON object.
 * The standard pattern is:
 *    key=value[ key=value]*
 *
 *  e.g.
 *    key1=val1 key2=val2 key3=val3
 *
 * ### Supported Syntax/Formats
 *  - A backslash character escapes the following character.
 *  - 'key' and 'value' can be enclosed in double quotation marks.
 *  - 'value' can contain spaces, whether quoted or not.
 *  - 'value' can contain multiple tokens enclosed in double quotation marks.
 *  - 'value' can be empty, whether quoted or not.
 *  - 'key' can contain spaces only if it is quoted or if the spaces are escaped.
 *  - Any spaces can be inserted between 'key' and 'value' around the '=' sign.
 *  - The 'key' of the next key=value pair can immediately follow the current key=value pair without any spaces, as long as at least one of the current 'value' or the next 'key' is quoted.
 *  - The following escape sequences are interpreted as control characters:
 *      * \b : backspace  
 *      * \f : form feed  
 *      * \n : line feed  
 *      * \r : carriage return  
 *      * \t : tab
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
 * You may get unexpected results if you provide text with incorrect patterns, as it does not perform validation.  
 * It is your responsibility to ensure the text is in the correct format before providing it.
 * However, you will not be able to validate the pattern using only RE2.
 * You can provide any text you like. It is recommended to use `_raw_kvobj->{}` to retrieve the entire JSON object and
 * verify its correctness, especially if the text is incorrectly formatted.  
 * 
 * :param __kvtext: A space-separated key=value text
 * :return _raw_kvobj: A JSON object generated from the key=value text
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
                "=(?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=\"]|[^=\\\"]))+?=|^(?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=\"]|[^=\\\"]))*?=|=(?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=\"]|[^=\\\"]))*?$"
            ),
            arrayindex(
                arraymap(
                    arraymap(
                        arraycreate(
                            regexcapture(to_string("@element"), "^(?:=\s*(?P<vkv>(?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=]|[^\\\"=]))*?)\s*(?P<vkk>\"(?:\\.|[^\\\"])*\"|(?:(?:\\==|\\[^=]|[^\\\"=\s])+))\s*=|\s*(?P<fk>\"(?:\\.|[^\\\"])*\"|(?:(?:\\==|\\[^=]|[^\\\"=])+))\s*=|=\s*(?P<lv>(?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=]|[^\\\"=]))*?)\s*)$")
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
                                // Encode to JSON string
                                replace(replace(replace(replace(replace(replace(replace(replace(
                                    arraystring(
                                        arraymap(
                                            split("@element", """\\\\"""),
                                            replace(replace(replace(replace(replace(replace("@element",
                                                "\n", convert_from_base_64("Cg==")),
                                                "\r", convert_from_base_64("DQ==")),
                                                "\t", convert_from_base_64("CQ==")),
                                                "\b", convert_from_base_64("CA==")),
                                                "\f", convert_from_base_64("DA==")),
                                                """\\""", ""
                                            )
                                        ),
                                        """\\"""
                                    ),
                                    convert_from_base_64("Cg=="), "\n"),
                                    convert_from_base_64("DQ=="), "\r"),
                                    convert_from_base_64("CQ=="), "\t"),
                                    convert_from_base_64("CA=="), "\b"),
                                    convert_from_base_64("DA=="), "\f"),
                                    """\\""", """\\\\"""),
                                    """\"""", """\\\""""),
                                    "/", """\\/"""
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
 * This rule transforms a comma-separated value into an array.
 * The standard pattern is:
 *    value[,value]*
 *
 *  e.g.
 *    val1,val2,val3
 *
 * ### Supported Syntax/Formats
 *  - A backslash character escapes the following character.
 *  - 'value' can be enclosed in double quotation marks.
 *  - A pair of double quotation marks ("") within a quoted value is converted to a single double quotation mark.
 *  - Any spaces can be allowed between a value and a comma separator.
 *  - The following escape sequences are treated as control characters:
 *      * \b : backspace
 *      * \f : form feed
 *      * \n : line feed
 *      * \r : carriage return
 *      * \t : tab
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
 * You may get unexpected results if you provide text with incorrect patterns, as it does not perform validation.
 * You should ensure the text is in the correct format using $PATTERN_CSV in advance, if necessary.
 *
 * :param __text: A comma-separated text
 * :return _columns: An array of column values
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
                    replace(replace(replace(replace(replace(replace("@element",
                        "\n", convert_from_base_64("Cg==")),
                        "\r", convert_from_base_64("DQ==")),
                        "\t", convert_from_base_64("CQ==")),
                        "\b", convert_from_base_64("CA==")),
                        "\f", convert_from_base_64("DA==")),
                        """\\""", ""
                    )
                ),
                """\\"""
            )
        ),
        0
    )
)
;

[RULE: minoue_xssv2array]
/***
 * This rule transforms a space-separated value into an array.
 * The standard pattern is:
 *    value[ value]*
 *
 *  e.g.
 *    val1 val2 val3
 *
 * 'value' can be enclosed in double quotation marks, and a backslash escapes the following character.
 *   e.g.
 *    - "value"
 *    - va\ lue
 *    - va\\lue
 *    - va\"lue
 *
 * The following escape sequences are interpreted as control codes.
 *  - \b : backspace
 *  - \f : form feed
 *  - \n : line feed
 *  - \r : carriage return
 *  - \t : tab
 *
 * :param __text: A space-separated text
 * :return _columns: An array of column values
 *
 * @auther Masahiko Inoue
 * @url https://github.com/spearmin10/xsiam-utils/blob/main/parsing-rules/minoue-parsing-rules.xql
 ***/
alter _columns = arraymap(
    regextract(
        to_string(coalesce(__text, "")),
        "((?:\"(?:\\.|[^\\\"])*\"|(?:\\.|[^\\\"\s]))+)\s*"
    ),
    arrayindex(
        arraymap(
            arraycreate(
                regexcapture(trim(to_string("@element")), "^\s*(?:\"(?P<qv>(?:\\.|[^\"])*)\"|(?P<nv>.*?))\s*$")
            ),
            if(
                "@element"->qv != "",
                arraystring(
                    arraymap(
                        split("@element"->qv, """\\\\"""),
                        replace(replace(replace(replace(replace(replace("@element",
                            "\n", convert_from_base_64("Cg==")),
                            "\r", convert_from_base_64("DQ==")),
                            "\t", convert_from_base_64("CQ==")),
                            "\b", convert_from_base_64("CA==")),
                            "\f", convert_from_base_64("DA==")),
                            """\\""", ""
                        )
                    ),
                    """\\"""
                ),
                arraystring(
                    arraymap(
                        split("@element"->nv, """\\\\"""),
                        replace(replace(replace(replace(replace(replace("@element",
                            "\n", convert_from_base_64("Cg==")),
                            "\r", convert_from_base_64("DQ==")),
                            "\t", convert_from_base_64("CQ==")),
                            "\b", convert_from_base_64("CA==")),
                            "\f", convert_from_base_64("DA==")),
                            """\\""", ""
                        )
                    ),
                    """\\"""
                )
            )
        ),
        0
    )
)
;

[RULE: minoue_syslog_lite]
/***
 * This rule extracts parameters from a syslog payload.
 * It supports both RFC 3164 and RFC 5424 log formats.
 *
 * The extracted parameters are saved in the 'syslog' field of a JSON object with the following structure.
 * However, 'syslog' will be null if the log is not in the correct format.
 * It does not support parsing SD-PARAM from the STRUCTURED-DATA in the RFC 5424 log,
 * so 'syslog.structured_data.params' will always be empty.
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
 * :param __log: The log to be parsed
 * :return syslog: The parameters extracted from the log, in a JSON object.
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
                "_raw", to_integer(_x->pri),
                "facility", arrayindex(
                    arraymap(
                        arraycreate(floor(divide(to_integer(_x->pri), 8))),
                        object_create(
                            "_raw", "@element",
                            "name", coalesce(arrayindex(split("kern,user,mail,daemon,auth,syslog,lpr,news,uucp,cron,authpriv,ftp,ntp,audit,alert,clock,local0,local1,local2,local3,local4,local5,local6,local7", ","), "@element"), "unknown")
                        )
                    ),
                    0
                ),
                "severity", arrayindex(
                    arraymap(
                        arraycreate(subtract(to_integer(_x->pri), multiply(floor(divide(to_integer(_x->pri), 8)), 8))),
                        object_create(
                            "_raw", "@element",
                            "name", arrayindex(split("emergency,alert,critical,error,warning,notice,informational,debug", ","), "@element")
                        )
                    ),
                    0
                )
            ),
            "version", to_integer(_x->version),
            "datetime", if(_x->datetime_5424 != "", _x->datetime_5424, if(_x->datetime_3164 != "", _x->datetime_3164)),
            "timestamp", if(
                _x->datetime_5424 = "",
                // time params - RFC 3164
                arrayindex(
                    arraymap(
                        arraymap(
                            arraymap(
                                arraycreate(
                                    object_create("now", current_time())
                                ),
                                object_create(
                                    "now_time", to_epoch("@element"->now, "SECONDS"),
                                    "log_time", to_epoch(
                                        parse_timestamp(
                                            "%Y %b %d %H:%M:%S",
                                            format_string("%d %s",
                                                add(
                                                    extract_time("@element"->now, "YEAR"),
                                                    if(
                                                        _x->mon = "Dec" and
                                                        _x->day = "31" and
                                                        extract_time("@element"->now, "MONTH") = 1 and
                                                        extract_time("@element"->now, "DAY") = 1,
                                                        -1,
                                                        if(
                                                            _x->mon = "Jan" and
                                                            _x->day = "1" and
                                                            extract_time("@element"->now, "MONTH") = 12 and
                                                            extract_time("@element"->now, "DAY") = 31,
                                                            1,
                                                            0
                                                        )
                                                    )
                                                ),
                                                _x->datetime_3164
                                            )
                                        ),
                                        "SECONDS"
                                    )
                                )
                            ),
                            object_create(
                                "log_time", "@element"->log_time,
                                "diff", subtract(to_integer("@element"->now_time), to_integer("@element"->log_time))
                            )
                        ),
                        if(
                            to_integer("@element"->diff) >= 50400 or to_integer("@element"->diff) <= -43200, // +14:00/-12:00
                            null,
                            timestamp_seconds(
                                add(
                                    to_integer("@element"->log_time),
                                    if(
                                        to_integer("@element"->diff) >= 0,
                                        subtract(
                                            add(to_integer("@element"->diff), 15),
                                            subtract(
                                                add(to_integer("@element"->diff), 15),
                                                multiply(floor(divide(add(to_integer("@element"->diff), 15), 30)), 30)
                                            )
                                        ),
                                        add(
                                            subtract(to_integer("@element"->diff), 15),
                                            subtract(
                                                subtract(multiply(to_integer("@element"->diff), -1), 15),
                                                multiply(floor(divide(subtract(multiply(to_integer("@element"->diff), -1), 15), 30)), 30)
                                            )
                                        )
                                    )
                                )
                            )
                        )
                    ),
                    0
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
            "pid", to_integer(_x->pid),
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
 * It supports both RFC 3164 and RFC 5424 log formats.
 *
 * The extracted parameters are saved in the 'syslog' field of a JSON object with the following structure.
 * However, 'syslog' will be null if the log is not in the correct format.
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
 * :param __log: The log to be parsed
 * :return _syslog: The parameters extracted from the log, in a JSON object.
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
                "_raw", to_integer(_x->pri),
                "facility", arrayindex(
                    arraymap(
                        arraycreate(floor(divide(to_integer(_x->pri), 8))),
                        object_create(
                            "_raw", "@element",
                            "name", coalesce(arrayindex(split("kern,user,mail,daemon,auth,syslog,lpr,news,uucp,cron,authpriv,ftp,ntp,audit,alert,clock,local0,local1,local2,local3,local4,local5,local6,local7", ","), "@element"), "unknown")
                        )
                    ),
                    0
                ),
                "severity", arrayindex(
                    arraymap(
                        arraycreate(subtract(to_integer(_x->pri), multiply(floor(divide(to_integer(_x->pri), 8)), 8))),
                        object_create(
                            "_raw", "@element",
                            "name", arrayindex(split("emergency,alert,critical,error,warning,notice,informational,debug", ","), "@element")
                        )
                    ),
                    0
                )
            ),
            "version", to_integer(_x->version),
            "datetime", if(_x->datetime_5424 != "", _x->datetime_5424, if(_x->datetime_3164 != "", _x->datetime_3164)),
            "timestamp", if(
                _x->datetime_5424 = "",
                // time params - RFC 3164
                arrayindex(
                    arraymap(
                        arraymap(
                            arraymap(
                                arraycreate(
                                    object_create("now", current_time())
                                ),
                                object_create(
                                    "now_time", to_epoch("@element"->now, "SECONDS"),
                                    "log_time", to_epoch(
                                        parse_timestamp(
                                            "%Y %b %d %H:%M:%S",
                                            format_string("%d %s",
                                                add(
                                                    extract_time("@element"->now, "YEAR"),
                                                    if(
                                                        _x->mon = "Dec" and
                                                        _x->day = "31" and
                                                        extract_time("@element"->now, "MONTH") = 1 and
                                                        extract_time("@element"->now, "DAY") = 1,
                                                        -1,
                                                        if(
                                                            _x->mon = "Jan" and
                                                            _x->day = "1" and
                                                            extract_time("@element"->now, "MONTH") = 12 and
                                                            extract_time("@element"->now, "DAY") = 31,
                                                            1,
                                                            0
                                                        )
                                                    )
                                                ),
                                                _x->datetime_3164
                                            )
                                        ),
                                        "SECONDS"
                                    )
                                )
                            ),
                            object_create(
                                "log_time", "@element"->log_time,
                                "diff", subtract(to_integer("@element"->now_time), to_integer("@element"->log_time))
                            )
                        ),
                        if(
                            to_integer("@element"->diff) >= 50400 or to_integer("@element"->diff) <= -43200, // +14:00/-12:00
                            null,
                            timestamp_seconds(
                                add(
                                    to_integer("@element"->log_time),
                                    if(
                                        to_integer("@element"->diff) >= 0,
                                        subtract(
                                            add(to_integer("@element"->diff), 15),
                                            subtract(
                                                add(to_integer("@element"->diff), 15),
                                                multiply(floor(divide(add(to_integer("@element"->diff), 15), 30)), 30)
                                            )
                                        ),
                                        add(
                                            subtract(to_integer("@element"->diff), 15),
                                            subtract(
                                                subtract(multiply(to_integer("@element"->diff), -1), 15),
                                                multiply(floor(divide(subtract(multiply(to_integer("@element"->diff), -1), 15), 30)), 30)
                                            )
                                        )
                                    )
                                )
                            )
                        )
                    ),
                    0
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
            "pid", to_integer(_x->pid),
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

[RULE: minoue_parse_cef]
/***
 * This rule parses the CEF parameters by detecting their pattern in the log message.
 *
 * The pattern is:
 *    CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
 *
 * The extracted parameters are saved in the '_cef' field of a JSON object with the following structure.  
 * However, '_cef' will be null if the CEF pattern is not found in the given log message.
 *
 *  {
 *    "_raw": <string>,
 *     "cef_version": <number>,
 *     "dev_vendor": <string>,
 *     "dev_product": <string>,
 *     "dev_version": <string>,
 *     "dev_event_class_id": <string>,
 *     "name": <string>,
 *     "severity": <string>,
 *     "extension": {
 *         "_raw": <string>,
 *         "params": {
 *          <param-key>: <param-value: string>
 *        }
 *     }
 *  }
 *
 * :param __log: A log message
 * :return _cef: The CEF parameters extracted from the log message
 *
 * @auther Masahiko Inoue
 * @url https://github.com/spearmin10/xsiam-utils/blob/main/parsing-rules/minoue-parsing-rules.xql
 ***/
alter _cef = regexcapture(
    to_string(__log),
    "(?:^|\s)(?P<cef_raw>CEF:\s*(?P<cef_version>\d+)\s*\|\s*(?P<dev_vendor>(?:\\.|[^|])*)\s*\|\s*(?P<dev_product>(?:\\.|[^|])*)\s*\|\s*(?P<dev_version>(?:\\.|[^|])*)\s*\|\s*(?P<dev_event_class_id>(?:\\.|[^|])*)\s*\|\s*(?P<name>(?:\\.|[^|])*)\s*\|\s*(?P<severity>(?:\\.|[^|])*)\s*\|\s*(?P<extension>.*))$"
)
| alter __kvtext = _cef->extension
| call minoue_nqsskv2kvobj

| alter _cef = if(
    _cef->cef_raw in (null, ""),
    null,
    arrayindex(
        arraymap(
            arraycreate(
                object_create(
                    "x",
                    arraymap(
                        arraycreate(
                            _cef->dev_vendor,
                            _cef->dev_product,
                            _cef->dev_version,
                            _cef->dev_event_class_id,
                            _cef->name,
                            _cef->severity
                        ),
                        arraystring(
                            arraymap(
                                split("@element", """\\\\"""),
                                replace(replace(replace(replace(replace(replace("@element",
                                    "\n", convert_from_base_64("Cg==")),
                                    "\r", convert_from_base_64("DQ==")),
                                    "\t", convert_from_base_64("CQ==")),
                                    "\b", convert_from_base_64("CA==")),
                                    "\f", convert_from_base_64("DA==")),
                                    """\\""", ""
                                )
                            ),
                            """\\"""
                        )
                    )
                )
            ),
            object_create(
                "cef_version", to_integer(_cef->cef_version),
                "dev_vendor", "@element"->x[0],
                "dev_product", "@element"->x[1],
                "dev_version", "@element"->x[2],
                "dev_event_class_id", "@element"->x[3],
                "name", "@element"->x[4],
                "severity", "@element"->x[5],
                "extension", object_create(
                    "_raw", _cef->extension,
                    "params", _raw_kvobj->{}
                )
            )
        ),
        0
    )
)

| fields - __kvtext, _raw_kvobj
;

/* ******* END OF MINOUE Parsing Rules Library **********
 * ******************************************************/
