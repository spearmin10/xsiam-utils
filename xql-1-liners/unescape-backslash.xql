/***
 * This expression unescapes an escaped text with backslash.
 * The following escape sequences are treated as control codes.
 *
 *  - \b : backspace
 *  - \f : form feed
 *  - \n : line feed
 *  - \r : carriage return
 *  - \t : tab
 *
 * :param __text: A text that can contain escaped charactors
 * :return __text: A text of characters with any escaped characters converted to their unescaped form.
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
    """me\"s\\\\sa\"ge"""
)
| arrayexpand __text

//
// Run
//
| alter __text = arraystring(
    arraymap(
        split(__text, """\\\\"""),
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

| fields __text
