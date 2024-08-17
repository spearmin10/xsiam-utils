/***
 * This expression transforms a space separated key=value text to a json object.
 * This is compatible with the `minoue_sskv2kvobj` rule.
 *
 * The standard pattern is:
 *    key=value[ key=value]*
 *
 *  e.g.
 *    - key1=val1 key2=val2 key3=val3
 *
 * 'key' and 'value' can be quoted with a double quotation mark, 'key' and 'value' between '=' allows any spaces to be inserted,
 * and also a backslash escapes a following charactor in quoted text.
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
 * You should ensure the text in the correct format with the PATTERN_SSKV below in advance.
 *
 * PATTERN_SSKV = "^(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^=\"\s])+)\s*?=\s*?(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^\"\s])*)(?:\s\s*(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^=\"\s])+)\s*=\s*(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^\"\s])*))*$"
 *
 * On the contrary, it will successfully return a JSON object without raising errors even if the text contains incorrect patterns.
 * You can give any texts if you want. It recommends to use `_raw_kvobj->{}` to get the entire JSON object in order to check if the return value is in the correct JSON object in case of incorrect text to be returned.
 *
 * :param __kvtext: A space separated key=value text
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
    "",
    "=",
    """key1=val1 key2=val2 key3=val3""",
    """\"key\"=\"value\"""",
    """key = value""",
    """key = \"value\"""",
    """\"k\\\"ey\" = \"va\\\\lue\"""",
    """key1=\"v a l 1\" key2=\"v a l 2\", key3=val3""",
    """key1=\"v a l 1\"key2=\"v a l 2\"""",
    """key1=\"v a l 1\",key2=\"v a l 2\"""",
    """key1=\"v a l 1\"\"key2\"=\"v a l 2\"""",
    """key1=\"v a l 1\",\"key2\"=\"v a l 2\""""
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
                    regextract(__kvtext, "(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^=\"\s])+)\s*?=\s*(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^\s])*)"),
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
                        replace(
                            replace(
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
        ","
    )
)

/**********
//
// 1-line
//

| alter _raw_kvobj = format_string("{%s}",arraystring(arraymap(arraymap(arraymap(regextract(__kvtext, "(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^=\"\s])+)\s*?=\s*(?:\"(?:\\.|[^\"])*\"|(?:\\.|[^\s])*)"),object_create("kv", split("@element", "="))),object_create("key", lowercase(trim("@element"->kv[0])),"val", trim(arraystring(arrayrange(json_extract_scalar_array("@element", "$.kv"), 1, 100000), "=")))),format_string("\"%s\"",arraystring(arraymap(arraycreate(if("@element"->key ~= "^\"", arrayindex(regextract("@element"->key, "\"((?:\\.|[^\"])*)\""), 0), "@element"->key),if("@element"->val ~= "^\"", arrayindex(regextract("@element"->val, "\"((?:\\.|[^\"])*)\""), 0), "@element"->val)),replace(replace(arraystring(arraymap(split("@element", """\\\\"""), replace("@element", """\\""", "")), """\\"""),"""\\""", """\\\\"""),"""\"""", """\\\"""")),"\":\""))),","))

**********/

| fields __kvtext, _raw_kvobj
