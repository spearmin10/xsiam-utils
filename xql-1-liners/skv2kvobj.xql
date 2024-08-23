/***
 * This expression transforms a separated keyed-value text to a json object.
 * Any of a charactor can be usable except for backslash and double quotation as the separator.
 *
 * This is compatible with the `minoue_skv2kvobj` rule.
 *
 * The standard pattern is:
 *    key<kv-separator>value[<ent-separator> key<kv-separator>value]*
 *
 *   e.g.
 *    key1=val1, key2=val2, key3=val3
 *    key1:val1; key2:val2; key3:val3
 *
 * ### Supported Syntax/Formats
 *  - The key-value separator (<kv-separator>) must be a charactor (length=1).
 *  - The entry separator (<ent-separator>) must be a charactor (length=1).
 *  - The key-value separator and the entry separator must be a different charactor.
 *  - The key-value separator and the entry are unable to be backslash and double quotation mark.
 *  - 'key' and 'value' can be quoted with a double quotation mark.
 *  - 'key' and 'value' between a key-value separator allows any spaces to be inserted.
 *  - `value` can contain any spaces.
 *  - A backslash escapes a following charactor in quoted text.
 *  - Any spaces can be allowed between a value and a key-value separator.
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
 *    - key1:v a l 1; key2: v a l 2
 *
 *  It also supports text separated with any entry separators and without an entry separator if `value` is quoted with a double quotation mark.
 *
 *   e.g.
 *    - key1:"v a l 1" key2:"v a l 2"; key3:val3
 *    - key1:"v a l 1"key2:"v a l 2"
 *    - key1:"v a l 1""key2":"v a l 2"
 *
 * You will get unexpected results if you give a text containing incorrect patterns as it doesn't check it.
 * It's responsible for you to make sure the text is in the correct pattern.
 * On the contrary, it will successfully return a JSON object without raising errors even if the text contains incorrect patterns.
 * You can give any texts if you want. It recommends to use `_raw_kvobj->{}` to get the entire JSON object in order to check if the return value is in the correct JSON object in case of incorrect text to be returned.
 *
 * :param __kvtext: A separated keyed-value text
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
    "key1:val1; key2:val2; key3:val3",
    "key1:v a l 1 ;key2: v a l 2; key3: v a l 3",
    "",
    ":",
    """\"key\":\"value\"""",
    """key : value""",
    """key : \"value\"""",
    """\"k\\\"ey\" : \"va\\\\lue\"""",
    """key1:\"v a l 1\" key2:\"v a l 2\"; key3:val3""",
    """key1:\"v a l 1\"key2:\"v a l 2\"""",
    """key1:\"v a l 1\"\"key2\":\"v a l 2\""""
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
            arraymap(
                arraymap(
                    regextract(
                        __kvtext,
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
                    object_create("kv", split("@element", __kv_separator))
                ),
                object_create(
                    "key", lowercase(trim("@element"->kv[0])),
                    "val", trim(arraystring(arrayrange(json_extract_scalar_array("@element", "$.kv"), 1, 100000), __kv_separator))
                )
            ),
            format_string(
                "\"%s\"",
                arraystring(
                    arraymap(
                        arraycreate(
                          if("@element"->key ~= "^\"", arrayindex(regextract("@element"->key, "\"((?:\\.|[^\"])*)\""), 0), "@element"->key),
                          if("@element"->val ~= "^\"", arrayindex(regextract("@element"->val, "\"((?:\\.|[^\"])*)\""), 0), "@element"->val)
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
                    "\":\""
                )
            )
        ),
        ","
    )
)

/**********
//
// 1-line
//

| alter _raw_kvobj = format_string("{%s}",arraystring(arraymap(arraymap(arraymap(regextract(__kvtext,replace(replace("(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^,=\"\s])+)\s*?=\s*(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^,])*)","=",__kv_separator),",",__ent_separator)),object_create("kv", split("@element", __kv_separator))),object_create("key", lowercase(trim("@element"->kv[0])),"val", trim(arraystring(arrayrange(json_extract_scalar_array("@element", "$.kv"), 1, 100000), __kv_separator)))),format_string("\"%s\"",arraystring(arraymap(arraycreate(if("@element"->key ~= "^\"", arrayindex(regextract("@element"->key, "\"((?:\\.|[^\"])*)\""), 0), "@element"->key),if("@element"->val ~= "^\"", arrayindex(regextract("@element"->val, "\"((?:\\.|[^\"])*)\""), 0), "@element"->val)),replace(replace(replace(replace(replace(replace(replace(replace(arraystring(arraymap(split("@element", """\\\\"""),replace(replace(replace(replace(replace(replace("@element","\n", convert_from_base_64("Cg==")),"\r", convert_from_base_64("DQ==")),"\t", convert_from_base_64("CQ==")),"\b", convert_from_base_64("CA==")),"\f", convert_from_base_64("DA==")),"""\\""", "")),"""\\"""),convert_from_base_64("Cg=="), "\n"),convert_from_base_64("DQ=="), "\r"),convert_from_base_64("CQ=="), "\t"),convert_from_base_64("CA=="), "\b"),convert_from_base_64("DA=="), "\f"),"""\\""", """\\\\"""),"""\"""", """\\\""""),"/", """\\/""")),"\":\""))),","))

**********/

| fields __kvtext, _raw_kvobj
