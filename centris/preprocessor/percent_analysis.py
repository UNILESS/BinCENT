import json

def analyze_kind_from_file(input_filepath):
    # 파일에서 데이터 불러오기
    with open(input_filepath, 'r', encoding='utf-8') as f:
        data = json.load(f)

    # 각 kind의 개수를 저장할 딕셔너리 초기화
    kind_counts = {}

    # 데이터의 총 항목 수
    total_items = len(data)

    # kind 별로 개수 계산
    for item in data:
        kind = item['hash'].split('|')[-1]
        kind_counts[kind] = kind_counts.get(kind, 0) + 1

    # kind 별 백분율 및 개수 저장
    kind_analysis = {}
    for kind, count in kind_counts.items():
        kind_analysis[kind] = {
            "count": count,
            "percentage": round((count / total_items) * 100, 2)
        }

    return kind_analysis

# 실행
input_file = "./componentDB/mirror@@busybox_sig"
result = analyze_kind_from_file(input_file)

# 백분율로 정렬하여 출력
sorted_result = sorted(result.items(), key=lambda x: x[1]['percentage'], reverse=True)
for kind, info in sorted_result:
    print(f"{kind}: Count - {info['count']}, Percentage - {info['percentage']}%")
print("\n")
print(input_file)
