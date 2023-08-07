import json

def analyze_kind_from_file(input_filepath, output_filepath):
    # 결과를 저장할 딕셔너리 초기화
    kind_counts = {}
    total_count = 0

    # 입력 파일 읽기
    with open(input_filepath, 'r', encoding='utf-8') as f:
        for line in f:
            # 총 개수 정보 추출
            if '@@' in line:
                total_count = float(line.split()[1])

            # '{'와 '}' 사이의 내용만 추출하여 각 아이템으로 분할
            items = line[line.find("{")+1:line.find("}")].split(',')

            for item in items:
                kind = item.split('|')[-1].replace("'", "").strip()
                kind_counts[kind] = kind_counts.get(kind, 0) + 1

    # 백분율 계산
    for kind, count in kind_counts.items():
        percentage = round((count / total_count) * 100, 2)
        kind_counts[kind] = {"count": count, "percentage": percentage}

    # 퍼센트가 높은 순서대로 정렬
    sorted_kind_counts = dict(sorted(kind_counts.items(), key=lambda item: item[1]['percentage'], reverse=True))

    # 결과를 JSON 파일로 저장
    with open(output_filepath, 'w', encoding='utf-8') as f:
        json.dump(sorted_kind_counts, f, ensure_ascii=False, indent=4)

    print(f"{output_filepath}에 분석 결과가 저장되었습니다.")

# 실행
input_file = "./res/result_busybox"
output_file = "busybox_analysis.json"  # 출력 파일명
analyze_kind_from_file(input_file, output_file)
