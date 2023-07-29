import os
import glob
import json
import re  # Regular expression library


def tokenize(file):
    with open(file, 'r') as f:
        content = f.read().lower()
        content = re.sub('[\n\t\",\\n\\t]', '', content)  # remove \n, \t, ", ,, \\n, and \\t
        # 스페이스를 기준으로 토큰화
        tokens = content.split(' ')
        # 각 토큰에서 공백 문자 제거
        tokens = [token.strip() for token in tokens if token.strip()]
    return set(tokens)


def analyze_repository(directory):
    result = set()
    for root, dirs, files in os.walk(directory):
        # .c와 .cpp 파일에 대해 순회
        for file in glob.glob(root + '/*.c') + glob.glob(root + '/*.cpp'):
            tokens = tokenize(file)
            result.update(tokens)

    # set을 list로 변환하고 각 항목을 'token' 키를 가진 딕셔너리로 만듦
    result_list = [{"token": item} for item in list(result)]

    with open(f'{directory}_result.json', 'w') as f:
        json.dump(result_list, f, indent=2)


analyze_repository('C:\\Users\\sunup\\PycharmProjects\\BinCENT\\src\\openssl-OpenSSL_1_0_1-stable')
