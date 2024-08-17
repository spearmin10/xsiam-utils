/***
 * This expression unquotes a text if quoted with a double quotation mark.
 * In addition, it unquotes escaped characters with a backslash.
 *
 * It doesn't unquote the text which has tokens outside the quoted text.
 *   e.g.
 *     - ` "token1" token2 `
 *
 * :param __text: A text that can be quoted.
 * :return __text: A text of characters with any escaped characters converted to the raw text.
 *
 * @auther Masahiko Inoue
 ***/

//
// Sample Texts
//
dataset = xdr_data 
| limit 1
| alter __text = arraycreate(
    """message""",
    """\"message\"""",
    """ \"message\" """,
    """ \"message\" """,
    """\"token1\" token2 \"token3\""""
)
| arrayexpand __text

//
// Run
//
| alter __text = arrayindex(
    arraymap(
        arraycreate(__text),
        arrayindex(
            arraymap(
                if(
                    "@element" ~= "^\s*\"(?:\\.|[^\"])*\"\s*$", 
                    regextract("@element", "^\s*\"((?:\\.|[^\"])*)\"\s*$"),
                    arraycreate("@element")
                ),
                arraystring(arraymap(split("@element", """\\\\"""), replace("@element", """\\""", "")), """\\""")
            ),
            0
        )
    ),
    0
)
| fields __text
