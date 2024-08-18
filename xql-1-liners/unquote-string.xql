/***
 * This expression unquotes a text if quoted with a double quotation mark.
 * In addition, it unquotes escaped characters with a backslash.
 *
 * The following escape sequences are treated as control codes.
 *
 *  - \b : backspace
 *  - \f : form feed
 *  - \n : line feed
 *  - \r : carriage return
 *  - \t : tab
 *
 * It doesn't unquote the text which has tokens outside the quoted text.
 *   e.g.
 *     - ` "token1" token2 `
 *
 * :param __text: A text that can be quoted.
 * :return __text: A text converted to the raw text.
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
    ),
    0
)

/**********
//
// 1-line
//

| alter __text = arrayindex(arraymap(arraycreate(__text),arrayindex(arraymap(if("@element" ~= "^\s*\"(?:\\.|[^\"])*\"\s*$", regextract("@element", "^\s*\"((?:\\.|[^\"])*)\"\s*$"),arraycreate("@element")),arraystring(arraymap(split("@element", """\\\\"""),replace(replace(replace(replace(replace(replace("@element","\n", convert_from_base_64("Cg==")),"\r", convert_from_base_64("DQ==")),"\t", convert_from_base_64("CQ==")),"\b", convert_from_base_64("CA==")),"\f", convert_from_base_64("DA==")),"""\\""", "")),"""\\""")),0)),0)

**********/

| fields __text
