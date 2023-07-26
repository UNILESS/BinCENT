import json
import os
import re
import subprocess

def extract_strings(file_content):
    string_pattern = r'\"([^"\\]*(\\.[^"\\]*)*)\"'
    matches = re.finditer(string_pattern, file_content)

    strings = []
    for match in matches:
        line_number = file_content.count('\n', 0, match.start()) + 1
        string_content = match.group().replace("\n", " ")  # remove newlines
        strings.append({"content": string_content, "line": line_number})
    return strings

def generate_tags(source_dir, output_dir):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    for root, _, files in os.walk(source_dir):
        for filename in files:
            if filename.endswith((".c", ".cpp")):
                source_path = os.path.join(root, filename)

                tags_output = subprocess.check_output(
                        'ctags' + ' -f - --kinds-C=* --fields=* --output-format=json "' + source_path + '"', stderr=subprocess.STDOUT,
                        shell=True).decode('utf-8')

                with open(source_path, "r") as source_file:
                    content = source_file.read()
                strings = extract_strings(content)

                lines = tags_output.split("\n")
                parsed_data = []
                for line in lines:
                    if line:
                        parsed_data.append(json.loads(line))

                # Add the strings to the appropriate tags
                for data in parsed_data:
                    if 'line' in data and 'end' in data:
                        for string in strings:
                            if data['line'] <= string['line'] <= data['end']:
                                if 'strings' in data:
                                    data['strings'].append(string['content'][1:-1])  # remove quotes
                                else:
                                    data['strings'] = [string['content'][1:-1]]  # remove quotes

                pretty_json = json.dumps(parsed_data, indent=2)

                output_filename = filename + ".json"
                output_path = os.path.join(output_dir, output_filename)

                with open(output_path, "w") as output_file:
                    output_file.write(pretty_json)


if __name__ == "__main__":
    source_directory = "C:\\Users\\JeongWooLee\\PycharmProjects\\BinCENT\\lua\\src"
    output_directory = ".\\output\\lua"

    generate_tags(source_directory, output_directory)
