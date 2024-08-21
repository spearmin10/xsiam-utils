/***
 * This expression transforms a comma separated key=value text to a json object.
 * This is compatible with the `minoue_cskv2kvobj` rule.
 *
 * The standard pattern is:
 *    key=value[, key=value]*
 *
 *   e.g.
 *    - key1=val1, key2=val2, key3=val3
 *
 * ### Supported Syntax/Formats
 *  - 'key' and 'value' can be quoted with a double quotation mark.
 *  - 'key' and 'value' between '=' allows any spaces to be inserted.
 *  - `value` can contain any spaces.
 *  - A backslash escapes a following charactor in quoted text.
 *  - Any spaces can be allowed between a value and a comma separator.
 *  - The following escape sequences are treated as control codes.
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
 *  It also supports text separated with any delimiters and without a delimiter if `value` is quoted with a double quotation mark.
 *  However $PATTERN_CSKV doesn't match the text because it is not comma separated keyed-value.
 *
 *   e.g.
 *    - key1="v a l 1" key2="v a l 2", key3=val3
 *    - key1="v a l 1"key2="v a l 2"
 *    - key1="v a l 1""key2"="v a l 2"
 *
 * You will get unexpected results if you give a text containing incorrect patterns as it doesn't check it.
 * You should ensure the text in the correct format with the PATTERN_CSV below in advance.
 *
 * PATTERN_CSKV = "^(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^,=\"\s])+)\s*?=\s*?(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^,\"\s])*)(?:,\s*(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^,=\"\s])+)\s*=\s*(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^,\"\s])*))*$"
 *
 * On the contrary, it will successfully return a JSON object without raising errors even if the text contains incorrect patterns.
 * You can give any texts if you want. It recommends to use `_raw_kvobj->{}` to get the entire JSON object in order to check if the return value is in the correct JSON object in case of incorrect text to be returned.
 *
 * :param __kvtext: A comma separated key=value text
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
    "key1=val1, key2=val2, key3=val3",
    "key1=v a l 1 ,key2= v a l 2, key3= v a l 3",
    "",
    "=",
    """\"key\"=\"value\"""",
    """key = value""",
    """key = \"value\"""",
    """\"k\\\"ey\" = \"va\\\\lue\"""",
    """key1=value1 key2=value2 key3=value3""",
    """key1=\"v a l 1\" key2=\"v a l 2\", key3=val3""",
    """key1=\"v a l 1\"key2=\"v a l 2\"""",
    """key1=\"v a l 1\"\"key2\"=\"v a l 2\""""
)
| arrayexpand __kvtext

//
// Run
//
| alter _raw_kvobj = format_string(
    "{%s}",
    arraystring(
        arraymap(
            arraymap(
                arraymap(
                    regextract(__kvtext, "(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^,=\"\s])+)\s*?=\s*(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^,])*)"),
                    object_create("kv", split("@element", "="))
                ),
                object_create(
                    "key", lowercase(trim("@element"->kv[0])),
                    "val", trim(arraystring(arrayrange(json_extract_scalar_array("@element", "$.kv"), 1, 100000), "="))
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

| alter _raw_kvobj = format_string("{%s}",arraystring(arraymap(arraymap(arraymap(regextract(__kvtext, "(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^,=\"\s])+)\s*?=\s*(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^,])*)"),object_create("kv", split("@element", "="))),object_create("key", lowercase(trim("@element"->kv[0])),"val", trim(arraystring(arrayrange(json_extract_scalar_array("@element", "$.kv"), 1, 100000), "=")))),format_string("\"%s\"",arraystring(arraymap(arraycreate(if("@element"->key ~= "^\"", arrayindex(regextract("@element"->key, "\"((?:\\.|[^\"])*)\""), 0), "@element"->key),if("@element"->val ~= "^\"", arrayindex(regextract("@element"->val, "\"((?:\\.|[^\"])*)\""), 0), "@element"->val)),replace(replace(replace(replace(replace(replace(replace(replace(arraystring(arraymap(split("@element", """\\\\"""),replace(replace(replace(replace(replace(replace("@element","\n", convert_from_base_64("Cg==")),"\r", convert_from_base_64("DQ==")),"\t", convert_from_base_64("CQ==")),"\b", convert_from_base_64("CA==")),"\f", convert_from_base_64("DA==")),"""\\""", "")),"""\\"""),convert_from_base_64("Cg=="), "\n"),convert_from_base_64("DQ=="), "\r"),convert_from_base_64("CQ=="), "\t"),convert_from_base_64("CA=="), "\b"),convert_from_base_64("DA=="), "\f"),"""\\""", """\\\\"""),"""\"""", """\\\""""),"/", """\\/""")),"\":\""))),","))

**********/

| fields __kvtext, _raw_kvobj
