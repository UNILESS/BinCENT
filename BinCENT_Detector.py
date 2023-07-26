import os
import json

def compare_key_values(directory, file2):
    with open(file2, 'r') as f:
        data2_list = json.load(f)

    for filename in os.listdir(directory):
        if filename.endswith(".json"):
            file1 = os.path.join(directory, filename)

            with open(file1, 'r') as f:
                data1 = json.load(f)

            for data2 in data2_list:
                name2 = data2.get('name') if data2.get('name') else ""
                strings2 = data2.get('strings') if data2.get('strings') else []

                if strings2:
                    strings2 = [s.get('string') for s in strings2 if s.get('string') and len(s.get('string')) > 2]

                if (name2 and len(name2) > 2) or strings2:
                    # Check each dict in data1
                    for d in data1:
                        name1 = d.get('name') if d.get('name') else ""
                        pattern1 = d.get('pattern') if d.get('pattern') else ""

                        if name1 and len(name1) > 2:
                            overlapping_names = [s for s in strings2 if s in name1]
                            if name2 and name2 in name1:
                                overlapping_names.append(name2)
                            if overlapping_names:
                                print(f"Overlap in 'name' detected in files {filename} and {file2} for '{name1}' with overlapping values: {overlapping_names}")

                        """if pattern1 and len(pattern1) > 2:
                            overlapping_patterns = [s for s in strings2 if s in pattern1]
                            if name2 and name2 in pattern1:
                                overlapping_patterns.append(name2)
                            if overlapping_patterns:
                                print(f"Overlap in 'pattern' detected in files {filename} and {file2} for '{pattern1}' with overlapping values: {overlapping_patterns}")"""

compare_key_values('./ctags/bx/src', 'crown-development.json')
