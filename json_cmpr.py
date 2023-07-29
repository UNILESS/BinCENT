import json


def compare_jsons(symbol_file, token_file):
    # load json files
    with open(symbol_file, 'r') as f:
        symbols = json.load(f)
    with open(token_file, 'r') as f:
        tokens = json.load(f)

    results = set()
    undetected_symbols = set()

    # iterate through symbols
    for symbol in symbols:
        symbol_detected = False
        symbol_val = symbol['symbol']
        symbol_type = symbol['type']

        # Ignore symbol if its length is 2 or less
        if len(symbol_val) <= 2:
            continue

        # iterate through tokens
        for token in tokens:
            token_val = token['token']
            if symbol_val in token_val:
                results.add((token_val, symbol_val, symbol_type))
                symbol_detected = True
        if not symbol_detected:
            undetected_symbols.add((symbol_val, symbol_type))

    # Convert set of tuples to list of dictionaries
    results = [
        {"Token": result[0], "Symbol": result[1], "Symbol Type": result[2]}
        for result in results
    ]

    # Convert undetected symbols to list of dictionaries
    undetected_symbols = [
        {"Symbol": symbol[0], "Symbol Type": symbol[1]}
        for symbol in undetected_symbols
    ]

    # Save results to json file
    with open('result.json', 'w') as f:
        json.dump(results, f, indent=2)

    # Save undetected symbols to another json file
    with open('undetected_symbols.json', 'w') as f:
        json.dump(undetected_symbols, f, indent=2)


# replace with your actual file paths
symbol_file = 'C:\\Users\\sunup\\PycharmProjects\\BinCENT\\openssl_result.json'
token_file = 'C:\\Users\\sunup\\PycharmProjects\\BinCENT\\src\\openssl-OpenSSL_1_0_1-stable_result.json'
compare_jsons(symbol_file, token_file)
