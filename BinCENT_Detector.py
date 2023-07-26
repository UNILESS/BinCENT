import os
import json
import tlsh
from collections import defaultdict

def calculate_tlsh_hash(feature):
    data = ''
    for key in sorted(feature.keys()):
        value = feature[key]
        data += f'{key}:{value}\n'
    return tlsh.hash(data.encode())

def calculate_tlsh_hashes(features):
    return set(calculate_tlsh_hash(feature) for feature in features)

def tlsh_similarity(hash1, hash2, threshold=100):
    diff = tlsh.diff(hash1, hash2)
    return diff <= threshold

def process_directory(directory_path):
    feature_hashes = defaultdict(set)
    for root, _, files in os.walk(directory_path):
        for file in files:
            if file.endswith('.json'):
                with open(os.path.join(root, file)) as f:
                    features = json.load(f)
                    file_feature_hashes = calculate_tlsh_hashes(features)
                    feature_hashes[os.path.join(root, file)] = file_feature_hashes
    return feature_hashes

# Load the features extracted from the source code
source_feature_hashes = process_directory('ctags\\')

# Load the features extracted from the binary code
with open('crown.json') as f:
    binary_features = json.load(f)
binary_feature_hashes = calculate_tlsh_hashes(binary_features)

# Threshold for similarity comparison
threshold = 30

# Check if the binary features contain the source code features for each source code file
for file, feature_hashes in source_feature_hashes.items():
    for hash_value in feature_hashes:
        for binary_hash in binary_feature_hashes:
            if tlsh_similarity(hash_value, binary_hash, threshold):
                print(f'The binary code contains a feature similar to the source code file: {file}')
                break
