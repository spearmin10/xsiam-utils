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
         "((?:\"(?:\\.|[^\\\"])*\"|(?:\\.|[^\\\"\s]))+)\s*"
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
