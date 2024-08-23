/***
 * This expression transforms a separated keyed-value text to a json object.
 * Any of a charactor can be usable except for backslash and double quotation as the separator.
 *
 * This is compatible with the `minoue_nqkv2kvobj` rule.
 *
 * The standard pattern is:
 *    key<kv-separator>value[<ent-separator> key<kv-separator>value]*
 *
 *  e.g.
 *    key1=val1, key2=val2, key3=val3
 *    key1:val1; key2:val2; key3:val3
 *
 * ### Supported Syntax/Formats
 *  - The Key-Value separator (<kv-separator>) must be a charactor (length=1).
 *  - The entry separator (<ent-separator>) must be a charactor (length=1).
 *  - The Key-Value separator and the entry separator must be a different charactor.
 *  - A backslash escapes a following charactor in quoted text.
 *  - Any spaces can be allowed between a value and a comma separator.
 *  - 'key' and 'value' can be quoted with a double quotation mark.
 *  - 'key' and 'value' between <kv-separator> allows any spaces to be inserted.
 *  - 'value' can contain spaces regardless the quoted text.
 *  - 'value' can contain multiple tokens quoted with a double quotation mark.
 *  - 'value' can be an empty value regardless the quoted text.
 *  - 'key' can contain any spaces only when it's quoted or a space in it is escaped.
 *  - 'key' of the next keyed-value can be placed immediately after the current keyed-value without a comma when at least one of the current 'value' or the next 'key' is quoted.
 *  - keyed-value can be delimited with any spaces when at least one of the current 'value' or the next 'key' is quoted.
 *  - The following escape sequences are treated as control codes.
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
 * You will get unexpected results if you give a text in incorrect patterns as it doesn't check it.
 * It's responsible for you to ensure the text in the correct format before giving it,
 * however you wouldn't be able to check the pattern only with RE2.
 * You can give any texts if you want. It recommends to use `_raw_kvobj->{}` to get the entire JSON object in order to check if the return value is in the correct JSON object in case of incorrect text to be returned.
 *
 * :param __kvtext: A comma separated key=value text
 * :param __ent_separator: An entry separator
 * :param __kv_separator: A key-value separator
 * :return _raw_kvobj: JSON object text
 *
 * @auther Masahiko Inoue
 ***/

//
// Sample Texts
//
dataset = xdr_data 
| limit 1
| alter __kvtext = arraycreate(
    """\"key\":\"value\"""",
    """key : value""",
    """key : \"value\"""",
    """\"k\\\"ey\" : \"va\\\\lue\"""",
    """key1:val\\;1; key2:val2""",
    """key1:v a l 1; key2: v a l 2""",
    """key1:\"v1[1]\" v1[2] \"v1[3]\"; key2:v2[1] \"v2[2]\"""",
    """key1 : ;key2 : \"\"""",
    """\"k e y 1\" : val1; key\\ 2 : val2""",
    """\"k e y 1\" : \"v a l 1\"key2 : \"v a l 2\"""",
    """\"key1\":\"val1\" \"key2\":\"val2\"""",
    """rule: 100; rule_uid: {00000000-0000-0000-0000-000000000000}; service_id: nbdatagram; src: 10.10.10.3; dst: 10.10.10.255; proto: udp; product: VPN-1 & FireWall-1; service: 138; s_port: 138;"""
)
| arrayexpand __kvtext

//
// Run
//
| alter __ent_separator = ";"
| alter __kv_separator = ":"

| alter _raw_kvobj = format_string(
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
                    arraycreate(
                        object_create(
                            "x",
                            arraymap(
                                arrayconcat(
                                    regextract(
                                        "@element",
                                        replace(
                                            replace(
                                                "^=\s*((?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=]|[^\\\"=]))*?)\s*,?\s*(?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=]|[^\\\"=\s])+)\s*=$",
                                                "=",
                                                __kv_separator
                                            ),
                                            ",",
                                            __ent_separator
                                        )
                                    ),
                                    regextract(
                                        "@element",
                                        replace(
                                            replace(
                                                "^=\s*(?:(?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=]|[^\\\"=]))*?)\s*,?\s*(\"(?:\\.|[^\\\"])*\"|(?:(?:\\==|\\[^=]|[^\\\"=\s])+))\s*=$",
                                                "=",
                                                __kv_separator
                                            ),
                                            ",",
                                            __ent_separator
                                        )
                                    ),
                                    regextract(
                                        "@element",
                                        replace(
                                            replace(
                                                "^(?:\s*(\"(?:\\.|[^\\\"])*\"|(?:(?:\\==|\\[^=]|[^\\\"=])+))\s*=)$",
                                                "=",
                                                __kv_separator
                                            ),
                                            ",",
                                            __ent_separator
                                        )
                                    ),
                                    regextract(
                                        "@element",
                                        replace(
                                            replace(
                                                "^(?:=\s*((?:\"(?:\\==|\\[^=]|[^\\\"])*\"|(?:\\==|\\[^=]|[^\\\"=]))*?)\s*)$",
                                                "=",
                                                __kv_separator
                                            ),
                                            ",",
                                            __ent_separator
                                        )
                                    )
                                ),
                                arrayindex(
                                    arraymap(
                                        arraymap(
                                            arraycreate(replace("@element", concat(__kv_separator, __kv_separator), __kv_separator)),
                                            if("@element" !~= "^\"((?:\\.|[^\"])*)\"$", "@element", arrayindex(regextract("@element", "^\"((?:\\.|[^\"])*)\"$"), 0))
                                        ),
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
                                    0
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

/**********
//
// 1-line
//

| alter _raw_kvobj = format_string("{%s}",arraystring(arraymap(regextract(replace(to_string(coalesce(__kvtext, "")), __kv_separator, concat(__kv_separator, __kv_separator)),replace("=(?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=\"]|[^=\\\"]))+?=|^(?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=\"]|[^=\\\"]))*?=|=(?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=\"]|[^=\\\"]))*?$","=",__kv_separator)),arrayindex(arraymap(arraycreate(object_create("x",arraymap(arrayconcat(regextract("@element",replace(replace("^=\s*((?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=]|[^\\\"=]))*?)\s*,?\s*(?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=]|[^\\\"=\s])+)\s*=$","=",__kv_separator),",",__ent_separator)),regextract("@element",replace(replace("^=\s*(?:(?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=]|[^\\\"=]))*?)\s*,?\s*(\"(?:\\.|[^\\\"])*\"|(?:(?:\\==|\\[^=]|[^\\\"=\s])+))\s*=$","=",__kv_separator),",",__ent_separator)),regextract("@element",replace(replace("^(?:\s*(\"(?:\\.|[^\\\"])*\"|(?:(?:\\==|\\[^=]|[^\\\"=])+))\s*=)$","=",__kv_separator),",",__ent_separator)),regextract("@element",replace(replace("^(?:=\s*((?:\"(?:\\==|\\[^=]|[^\\\"])*\"|(?:\\==|\\[^=]|[^\\\"=]))*?)\s*)$","=",__kv_separator),",",__ent_separator))),arrayindex(arraymap(arraymap(arraycreate(replace("@element", concat(__kv_separator, __kv_separator), __kv_separator)),if("@element" !~= "^\"((?:\\.|[^\"])*)\"$", "@element", arrayindex(regextract("@element", "^\"((?:\\.|[^\"])*)\"$"), 0))),replace(replace(replace(replace(replace(replace(replace(replace(arraystring(arraymap(split("@element", """\\\\"""),replace(replace(replace(replace(replace(replace("@element","\n", convert_from_base_64("Cg==")),"\r", convert_from_base_64("DQ==")),"\t", convert_from_base_64("CQ==")),"\b", convert_from_base_64("CA==")),"\f", convert_from_base_64("DA==")),"""\\""", "")),"""\\"""),convert_from_base_64("Cg=="), "\n"),convert_from_base_64("DQ=="), "\r"),convert_from_base_64("CQ=="), "\t"),convert_from_base_64("CA=="), "\b"),convert_from_base_64("DA=="), "\f"),"""\\""", """\\\\"""),"""\"""", """\\\""""),"/", """\\/""")),0)))),if(array_length("@element"->x[]) = 2,format_string("\"%s\",\"%s\"", "@element"->x[0], "@element"->x[1]),format_string("\"%s\"", "@element"->x[0]))),0)),":"))

**********/

| fields __kvtext, _raw_kvobj
