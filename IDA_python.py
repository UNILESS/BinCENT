import idaapi
import idautils
import idc
import json
import string

# Make a set of printable and non-space characters
printable_and_nonspace = set(string.ascii_letters + string.digits + string.punctuation)


def get_function_signature(func):
    sig = idc.GetType(func.startEA)
    return sig if sig else "unknown"


def get_name_and_kind(func):
    name = idc.GetFunctionName(func.startEA)
    if name:  # If name is not None or empty string
        kind = "function"
    else:
        name = idc.Name(func.startEA)
        if name:
            kind = "variable"
        else:
            kind = "unknown"
    return name, kind




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
    for func in idautils.Functions():
        f = idaapi.get_func(func)
        if f:
            name, kind = get_name_and_kind(f)
            feature = {
                "_type": "tag",
                "name": name,
                "path": idc.GetInputFilePath(),
                "file": True,
                "language": "binary",
                "typeref": "typename:" + get_function_signature(f),
                "kind": kind,
                "signature": get_function_signature(f),
                "roles": "unknown",
                "extras": "unknown",
                "end": f.endEA,
            }
            data.append(feature)

    data.append({"strings": all_strings})  # add all strings at the end

    with open("output.json", "w") as outfile:
        json.dump(data, outfile, indent=4)


if __name__ == "__main__":
    extract_features()
