/***
 * This expression transforms a space separated value to an array.
 * This is compatible with the `minoue_ssv2array` rule.
 *
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
 ***/

//
// Sample Texts
//

dataset = xdr_data
| limit 1
| alter __text = arraycreate(
    """val1 val2 val3""",
    """\"value\"""",
    """va\\ lue""",
    """va\\\\lue""",
    """va\\\"lue""",
    """val\\1 val\\ 2 \"val 3\""""
)
| arrayexpand __text

//
// Run
//
| alter _columns = arraymap(
     regextract(
         to_string(coalesce(__text, "")),
         "(?:\"(?:\\.|[^\\\"])*\"|(?:\\.|[^\\\s]))+\s+|(?:\"(?:\\.|[^\\\"])*\"|(?:\\.|[^\\\s]))+$"
     ),
     arrayindex(
         arraymap(
            if(
                "@element" ~= "^\s*\"((?:\\.|[^\"])*)\"\s*$",
                regextract("@element", "^\s*\"((?:\\.|[^\"])*)\"\s*$"),
                regextract("@element", "^\s*((?:\\.|[^\s])*)\s*$")
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
| fields __text, _columns
