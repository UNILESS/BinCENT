import os
import subprocess
import json
import traceback

def analyze_binary_repository(repoPath):
    # Set to store unique symbols and their types
    symbol_set = set()
    fileCnt = 0

    for path, dir, files in os.walk(repoPath):
        for file in files:
            filePath = os.path.join(path, file)

            try:
                # Execute radare2 command to get symbols
                process = subprocess.Popen('radare2 -A -e bin.cache=true -c "islj" "' + filePath + '"',
                                           stdout=subprocess.PIPE,
                                           stdin=subprocess.PIPE,
                                           shell=True)
                output, error = process.communicate(input=b'y\n')

                # Decode bytes to string and split the string into individual JSON objects
                output_str = output.decode()
                output_str = output_str.split(']}')[0] + ']}'

                json_obj = json.loads(output_str)

                # Extract symbols from the JSON object
                symbols = json_obj["symbols"]

                fileCnt += 1

                for symbol in symbols:
                    # Use the symbol names directly
                    normalizedSymbol = symbol["realname"].lower().replace("\n", "")
                    symbolType = symbol["type"]

                    # Only add the symbol-type pair to the set if the symbol is not empty
                    if normalizedSymbol:
                        symbol_info = { 'symbol': normalizedSymbol, 'type': symbolType }
                        symbol_set.add(json.dumps(symbol_info))  # sets do not accept dict type, so we convert it to str

            except subprocess.CalledProcessError as e:
                print("Parser Error:", e)
                traceback.print_exc()
                continue
            except Exception as e:
                print("Subprocess failed", e)
                traceback.print_exc()
                continue

    # Convert back to dict
    symbol_list = [json.loads(i) for i in symbol_set]

    # Get the directory name and use it to name the result file
    dir_name = os.path.basename(os.path.normpath(repoPath))
    result_file = dir_name + '_result.json'

    # Save the result as a json file
    with open(result_file, 'w') as f:
        json.dump(symbol_list, f, indent=2)

    return symbol_list, fileCnt

analyze_binary_repository('C:\\Users\\sunup\\PycharmProjects\\BinCENT\\centris\\detector\\openssl')
