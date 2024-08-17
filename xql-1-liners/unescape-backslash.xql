/***
 * This expression unescapes an escaped text with backslash.
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
| alter __text = arraystring(arraymap(split(__text, """\\\\"""), replace("@element", """\\""", "")), """\\""")
| fields __text
