import os
import json
from collections import OrderedDict

def compare_key_values(directory, file2):
    result_directory = './result'
    os.makedirs(result_directory, exist_ok=True)  # Create 'result' directory if it doesn't exist

    with open(file2, 'r') as f:
        data2_list = json.load(f)

    overlap_results = {}  # Store results in a dict

    for root, dirs, files in os.walk(directory):
        for filename in files:
            if filename.endswith(".json"):
                file1 = os.path.join(root, filename)

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
                                    dir_name = os.path.basename(root)  # Get directory name
                                    if dir_name not in overlap_results:
                                        overlap_results[dir_name] = {}
                                    if name1 not in overlap_results[dir_name]:
                                        overlap_results[dir_name][name1] = {
                                            'count': 0,
                                            'overlaps': set()  # Change made here
                                        }
                                    overlap_results[dir_name][name1]['count'] += 1
                                    overlap_results[dir_name][name1]['overlaps'].update(overlapping_names)  # Change made here

    # Write results to JSON file
    with open(os.path.join(result_directory, 'overlap_results.json'), 'w') as f:
        # Convert sets to lists before writing to file
        for dir_name, names in overlap_results.items():
            # Sort by count and convert the sorted results to a dictionary
            sorted_results = OrderedDict(sorted(names.items(), key=lambda item: item[1]['count'], reverse=True))
            for name, info in sorted_results.items():
                info['overlaps'] = list(info['overlaps'])
            overlap_results[dir_name] = sorted_results
        json.dump(overlap_results, f, indent=4)

compare_key_values('./ctags/', 'crown-development.json')
