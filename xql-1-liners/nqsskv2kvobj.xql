/***
 * This expression transforms a space separated key=value text to a json object.
 * This is compatible with the `minoue_nqsskv2kvobj` rule.
 *
 * The standard pattern is:
 *    key=value[ key=value]*
 *
 *  e.g.
 *    key1=val1 key2=val2 key3=val3
 *
 * ### Supported Syntax/Formats
 *  - A backslash charator escapes a following charactor.
 *  - 'key' and 'value' can be quoted with a double quotation mark.
 *  - 'value' can contain spaces regardless the quoted text.
 *  - 'value' can contain multiple tokens quoted with a double quotation mark.
 *  - 'value' can be an empty value regardless the quoted text.
 *  - 'key' can contain any spaces only when it's quoted or a space in it is escaped.
 *  - 'key' and 'value' between '=' allows any spaces to be inserted.
 *  - 'key' of the next key=value can be placed immediately after the current key=value without any spaces when at least one of the current 'value' or the next 'key' is quoted.
 *  - The following escape sequences are treated as control codes.
 *      * \b : backspace
 *      * \f : form feed
 *      * \n : line feed
 *      * \r : carriage return
 *      * \t : tab
 *
 *   e.g.
 *    - key1="val1" key2="val2"
 *    - key1="val=1" key2="val=2"
 *    - key1="va\\l1" key2="va\\l2"
 *    - key1=v a l 1 key2=v a l 2
 *    - "key1"="val1" "key2"="val2"
 *    - key1 = val1 key2 = val2
 *    - key1 = val1 key2 = "v a l 2"
 *    - key1=val\=1 key2=val\=2
 *    - "k e y 1" = "v a l 1"key2 = "v a l 2"
 *    - "k e y 1" = val1"k e y 2" = "v a l 2"
 *    - "k e y 1" = "v a l 1" "k e y 2" = "v a l 2"
 *    - "k e y 1" = "v a l 1""k e y 2" = "v a l 2"
 *    - key1="v1[1]" v1[2] "v1[3]" key2=v2[1] "v2[2]"
 *    - key1="" key2= key3=
 *
 * You will get unexpected results if you give a text in incorrect patterns as it doesn't check it.
 * It's responsible for you to ensure the text in the correct format before giving it,
 * however you wouldn't be able to check the pattern only with RE2.
 * You can give any texts if you want. It recommends to use `_raw_kvobj->{}` to get the entire JSON object in order to check if the return value is in the correct JSON object in case of incorrect text to be returned.
 *
 * :param __kvtext: A space separated key=value text (__kvtext will be broken in the function)
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
    """key1=\"val1\" key2=\"val2\"""",
    """key1=\"val=1\" key2=\"val=2\"""",
    """key1=\"va\\\\l1\" key2=\"va\\\\l2\"""",
    """key1=v a l 1 key2=v a l 2""",
    """\"key1\"=\"val1\" \"key2\"=\"val2\"""",
    """key1 = val1 key2 = val2""",
    """key1 = val1 key2 = \"v a l 2\"""",
    """key1=val\\=1 key2=val\\=2""",
    """\"k e y 1\" = \"v a l 1\"key2 = \"v a l 2\"""",
    """\"k e y 1\" = val1\"k e y 2\" = \"v a l 2\"""",
    """\"k e y 1\" = \"v a l 1\" \"k e y 2\" = \"v a l 2\"""",
    """\"k e y 1\" = \"v a l 1\"\"k e y 2\" = \"v a l 2\"""",
    """key1=\"v1[1]\" v1[2] \"v1[3]\" key2=v2[1] \"v2[2]\"""",
    """key1=\"\" key2= key3=""",
    """=""",
    """end=1722914641722 shost=test-pc suser=['NT AUTHORITY\\\\\\\\SYSTEM'] deviceFacility=None cat=Persistence externalId=5907647 request=https://xdr20japan.xdr.us.paloaltonetworks.com/alerts/5907647 fs1=False fs1Label=Starred fs2=False fs2Label=Excluded cs1=schtasks.exe cs1Label=Initiated by cs2=\"schtasks.exe\" /Change /TN \"\\\\Microsoft\\\\Office\\\\IMESharePointDictionary\" /TR \"\\\\\"c:\\\\Program Files\\\\Common Files\\\\Microsoft Shared\\\\IME16\\\\IMESharePointDictionary.exe\\\\\" -updateall \" cs2Label=Initiator CMD cs3=SIGNATURE_SIGNED-Microsoft Corporation cs3Label=Signature cs4=schtasks.exe cs4Label=CGO name cs5=\"schtasks.exe\" /Change /TN \"\\\\Microsoft\\\\Office\\\\IMESharePointDictionary\" /TR \"\\\\\"c:\\\\Program Files\\\\Common Files\\\\Microsoft Shared\\\\IME16\\\\IMESharePointDictionary.exe\\\\\" -updateall \" cs5Label=CGO CMD cs6=SIGNATURE_SIGNED-Microsoft Corporation cs6Label=CGO Signature fileHash=f0024eb58326ecae6437237c3125ce75be6c621ea4b1303fd5b9dfe96b1dff32 filePath=C:\\\\Windows\\\\SysWOW64\\\\schtasks.exe targetprocesssignature=None-None tenantname=Palo Alto Networks - CoreCortex JAPAN - Cortex XDR tenantCDLid=1410944177 CSPaccountname=Palo Alto Networks - CoreCortex JAPAN initiatorSha256=f0024eb58326ecae6437237c3125ce75be6c621ea4b1303fd5b9dfe96b1dff32 initiatorPath=C:\\\\Windows\\\\SysWOW64\\\\schtasks.exe cgoSha256=f0024eb58326ecae6437237c3125ce75be6c621ea4b1303fd5b9dfe96b1dff32 osParentName=svchost.exe osParentCmd=C:\\\\WINDOWS\\\\system32\\\\svchost.exe -k netsvcs -p -s Schedule osParentSha256=949bfb5b4c7d58d92f3f9c5f8ec7ca4ceaffd10ec5f0020f0a987c472d61c54b osParentSignature=SIGNATURE_SIGNED osParentSigner=Microsoft Corporation act=Detected"""
)
| arrayexpand __kvtext

//
// Run
//
| alter _raw_kvobj = format_string(
    "{%s}",
    arraystring(
        arraymap(
            regextract(
                replace(to_string(coalesce(__kvtext, "")), "=", "=="),
                "=(?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=\"]|[^=\\\"]))+?=|^(?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=\"]|[^=\\\"]))*?=|=(?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=\"]|[^=\\\"]))*?$"
            ),
            arrayindex(
                arraymap(
                    arraycreate(
                        object_create(
                            "x",
                            arraymap(
                                arrayconcat(
                                    regextract("@element", "^=\s*((?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=]|[^\\\"=]))*?)\s*(?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=]|[^\\\"=\s])+)\s*=$"),
                                    regextract("@element", "^=\s*(?:(?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=]|[^\\\"=]))*?)\s*(\"(?:\\.|[^\\\"])*\"|(?:(?:\\==|\\[^=]|[^\\\"=\s])+))\s*=$"),
                                    regextract("@element", "^(?:\s*(\"(?:\\.|[^\\\"])*\"|(?:(?:\\==|\\[^=]|[^\\\"=])+))\s*=)$"),
                                    regextract("@element", "^(?:=\s*((?:\"(?:\\==|\\[^=]|[^\\\"])*\"|(?:\\==|\\[^=]|[^\\\"=]))*?)\s*)$")
                                ),
                                arrayindex(
                                    arraymap(
                                        arraymap(
                                            arraycreate(replace("@element", "==", "=")),
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

| alter _raw_kvobj = format_string("{%s}",arraystring(arraymap(regextract(replace(to_string(coalesce(__kvtext, "")), "=", "=="),"=(?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=\"]|[^=\\\"]))+?=|^(?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=\"]|[^=\\\"]))*?=|=(?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=\"]|[^=\\\"]))*?$"),arrayindex(arraymap(arraycreate(object_create("x",arraymap(arrayconcat(regextract("@element", "^=\s*((?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=]|[^\\\"=]))*?)\s*(?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=]|[^\\\"=\s])+)\s*=$"),regextract("@element", "^=\s*(?:(?:\"(?:\\.|[^\\\"])*\"|(?:\\==|\\[^=]|[^\\\"=]))*?)\s*(\"(?:\\.|[^\\\"])*\"|(?:(?:\\==|\\[^=]|[^\\\"=\s])+))\s*=$"),regextract("@element", "^(?:\s*(\"(?:\\.|[^\\\"])*\"|(?:(?:\\==|\\[^=]|[^\\\"=])+))\s*=)$"),regextract("@element", "^(?:=\s*((?:\"(?:\\==|\\[^=]|[^\\\"])*\"|(?:\\==|\\[^=]|[^\\\"=]))*?)\s*)$")),arrayindex(arraymap(arraymap(arraycreate(replace("@element", "==", "=")),if("@element" !~= "^\"((?:\\.|[^\"])*)\"$", "@element", arrayindex(regextract("@element", "^\"((?:\\.|[^\"])*)\"$"), 0))),replace(replace(replace(replace(replace(replace(replace(replace(arraystring(arraymap(split("@element", """\\\\"""),replace(replace(replace(replace(replace(replace("@element","\n", convert_from_base_64("Cg==")),"\r", convert_from_base_64("DQ==")),"\t", convert_from_base_64("CQ==")),"\b", convert_from_base_64("CA==")),"\f", convert_from_base_64("DA==")),"""\\""", "")),"""\\"""),convert_from_base_64("Cg=="), "\n"),convert_from_base_64("DQ=="), "\r"),convert_from_base_64("CQ=="), "\t"),convert_from_base_64("CA=="), "\b"),convert_from_base_64("DA=="), "\f"),"""\\""", """\\\\"""),"""\"""", """\\\""""),"/", """\\/""")),0)))),if(array_length("@element"->x[]) = 2,format_string("\"%s\",\"%s\"", "@element"->x[0], "@element"->x[1]),format_string("\"%s\"", "@element"->x[0]))),0)),":"))

**********/

| fields __kvtext, _raw_kvobj
