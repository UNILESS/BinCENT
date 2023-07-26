import idaapi
import idautils
import idc
import json
import string

# Make a set of printable and non-space characters
printable_and_nonspace = set(string.ascii_letters + string.digits + string.punctuation)


def get_function_signature(ea):
    sig = idc.GetType(ea)
    return sig if sig else "unknown"


def get_name_and_kind(ea):
    if idaapi.isFunc(ea):
        return idc.GetFunctionName(ea), "function"
    elif idaapi.isData(idaapi.getFlags(ea)):
        name = idc.GetTrueName(ea) if idc.GetTrueName(ea) else idc.Name(ea)
        if idc.GetFunctionName(ea):
            return name, "local variable"
        else:
            return name, "global variable"
    else:
        return "", "unknown"



def clean_string(s):
    return ''.join(c for c in s if c in printable_and_nonspace)


def get_all_strings():
    strings = []
    for s in idautils.Strings():
        # Clean the string and replace the new line characters with a space
        clean_s = clean_string(str(s)).replace("\n", " ")
        strings.append({
            "ea": s.ea,
            "string": clean_s
        })
    return strings


def extract_features():
    all_strings = get_all_strings()

    data = []

    # First extract all functions
    for func in idautils.Functions():
        f = idaapi.get_func(func)
        if f:
            name = idc.GetFunctionName(f.startEA)
            feature = {
                "_type": "tag",
                "name": name,
                "path": idc.GetInputFilePath(),
                "file": True,
                "language": "binary",
                "typeref": "typename:" + get_function_signature(f.startEA),
                "kind": "function",
                "signature": get_function_signature(f.startEA),
                "roles": "unknown",
                "extras": "unknown",
                "end": f.endEA,
            }
            data.append(feature)

    # Then extract all variables and constants
    for seg_ea in idautils.Segments():
        for ea in idautils.Heads(seg_ea, idc.SegEnd(seg_ea)):
            if not idaapi.isFunc(ea):  # Skip if it's a function
                name, kind = get_name_and_kind(ea)
                if name:  # If name is not None or empty string
                    feature = {
                        "_type": "tag",
                        "name": name,
                        "path": idc.GetInputFilePath(),
                        "file": True,
                        "language": "binary",
                        "typeref": "typename:" + get_function_signature(ea),
                        "kind": kind,
                        "signature": get_function_signature(ea),
                        "roles": "unknown",
                        "extras": "unknown",
                        "end": idc.SegEnd(seg_ea),
                    }
                    data.append(feature)

    data.append({"strings": all_strings})  # add all strings at the end

    with open("output.json", "w") as outfile:
        json.dump(data, outfile, indent=2)


if __name__ == "__main__":
    extract_features()