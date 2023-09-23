"""
Detector.
Author:		Seunghoon Woo (seunghoonwoo@korea.ac.kr)
Modified: 	December 16, 2020.
"""

import os
import sys
# sys.path.insert(0, "../osscollector")
# import OSS_Collector
import subprocess
import re
import shutil
import json
import traceback
import r2pipe

"""GLOBALS"""
currentPath = os.getcwd()
theta = 0
resultPath = currentPath + "/res/"
repoFuncPath = "/home/jeongwoo/PycharmProjects/BinCENT_2nd/centris/osscollector/repo_functions"
verIDXpath = "/home/jeongwoo/PycharmProjects/BinCENT_2nd/centris/preprocessor/verIDX/"
initialDBPath = "/home/jeongwoo/PycharmProjects/BinCENT_2nd/centris/preprocessor/initialSigs/"
finalDBPath = "/home/jeongwoo/PycharmProjects/BinCENT_2nd/centris/preprocessor/componentDB/"
metaPath = "/home/jeongwoo/PycharmProjects/BinCENT_2nd/centris/preprocessor/metaInfos/"
aveFuncPath = metaPath + "aveFuncs"
weightPath = metaPath + "weights/"
ctagsPath = "ctags"

shouldMake = [resultPath]
for eachRepo in shouldMake:
    if not os.path.isdir(eachRepo):
        os.mkdir(eachRepo)


def removeComment(string):
    # Code for removing C/C++ style comments. (Imported from VUDDY and ReDeBug.)
    # ref: https://github.com/squizz617/vuddy
    c_regex = re.compile(
        r'(?P<comment>//.*?$|[{}]+)|(?P<multilinecomment>/\*.*?\*/)|(?P<noncomment>\'(\\.|[^\\\'])*\'|"(\\.|[^\\"])*"|.[^/\'"]*)',
        re.DOTALL | re.MULTILINE)
    return ''.join([c.group('noncomment') for c in c_regex.finditer(string) if c.group('noncomment')])


def normalize(string):
    # Code for normalizing the input string.
    # LF and TAB literals, curly braces, and spaces are removed,
    # and all characters are lowercased.
    # ref: https://github.com/squizz617/vuddy
    return ''.join(string.replace('\n', '').replace('\r', '').replace('\t', '').replace('{', '').replace('}', '').split(
        ' ')).lower()



import struct

def extract_various_data(data_bytes):
    data_fragments = []

    # Extract 2-byte integers
    for i in range(0, len(data_bytes) - 1, 2):  # Ensure we have 2 bytes left
        int_val = struct.unpack('<H', data_bytes[i:i+2])[0]
        if int_val != 0:
            data_fragments.append(f"{int_val}")

    # Extract 4-byte integers
    for i in range(0, len(data_bytes) - 3, 4):  # Ensure we have 4 bytes left
        int_val = struct.unpack('<I', data_bytes[i:i+4])[0]
        if int_val != 0:
            data_fragments.append(f"{int_val}")

    # Extract 8-byte integers
    for i in range(0, len(data_bytes) - 7, 8):  # Ensure we have 8 bytes left
        int_val = struct.unpack('<Q', data_bytes[i:i+8])[0]
        if int_val != 0:
            data_fragments.append(f"{int_val}")

    # Extract 4-byte floats
    for i in range(0, len(data_bytes) - 3, 4):  # Ensure we have 4 bytes left
        float_val = struct.unpack('<f', data_bytes[i:i+4])[0]
        if float_val != 0.0:
            data_fragments.append(f"{float_val}")

    # Extract 8-byte floats (double)
    for i in range(0, len(data_bytes) - 7, 8):  # Ensure we have 8 bytes left
        double_val = struct.unpack('<d', data_bytes[i:i+8])[0]
        if double_val != 0.0:
            data_fragments.append(f"{double_val}")

    return data_fragments

def extract_symbols_and_data(repoPath):
    resDict = {}
    fileCnt = 0

    for path, dir, files in os.walk(repoPath):
        for file in files:
            filePath = os.path.join(path, file)

            try:
                r2 = r2pipe.open(filePath)
                r2.cmd('aaa')  # Analyze all

                # Extracting strings
                symbols = r2.cmdj('izj')
                for symbol in symbols:
                    normalizedSymbol = normalize(symbol["string"]) if symbol["string"] else normalize(symbol["name"])
                    store_in_resDict(normalizedSymbol, filePath, resDict, repoPath)

                # Extracting exported functions
                functions = r2.cmdj('aflj')
                for func in functions:
                    if func["name"].startswith("sym."):
                        normalizedFunc = normalize(func["name"])
                        store_in_resDict(normalizedFunc, filePath, resDict, repoPath)

                # Check if the data section exists
                sections = r2.cmdj('iSj')
                data_section = next((s for s in sections if s.get('name') == '.data'), None)
                if data_section:
                    offset = data_section['vaddr']
                    size = data_section['vsize']
                    hex_data = r2.cmd(f'p8 {size} @ {offset}')
                    data_bytes = bytes.fromhex(hex_data)
                else:
                    print(f"No data section in file {filePath}")
                    continue

                data_fragments = extract_various_data(data_bytes)
                for data_fragment in data_fragments:
                    normalizedData = normalize(str(data_fragment))
                    store_in_resDict(normalizedData, filePath, resDict, repoPath)

                fileCnt += 1

            except Exception as e:
                print("Subprocess failed", e)
                traceback.print_exc()
                continue

    return resDict, fileCnt

def store_in_resDict(normalizedSymbol, filePath, resDict, repoPath):
    storedPath = filePath.replace(repoPath, "")
    if normalizedSymbol not in resDict:
        resDict[normalizedSymbol] = []
    resDict[normalizedSymbol].append(storedPath)

def getAveFuncs():
    aveFuncs = {}
    with open(aveFuncPath, 'r', encoding="UTF-8") as fp:
        aveFuncs = json.load(fp)
    return aveFuncs


def readComponentDB():
    componentDB = {}
    jsonLst = []

    for OSS in os.listdir(finalDBPath):
        componentDB[OSS] = []
        with open(finalDBPath + OSS, 'r', encoding="UTF-8") as fp:
            jsonLst = json.load(fp)

            for eachHash in jsonLst:
                hashval = eachHash["hash"]
                normalized_hashval = normalize(hashval)
                componentDB[OSS].append(normalized_hashval)

    return componentDB


def readAllVers(repoName):
    allVerList = []
    idx2Ver = {}

    with open(verIDXpath + repoName + "_idx", 'r', encoding="UTF-8") as fp:
        tempVerList = json.load(fp)

        for eachVer in tempVerList:
            allVerList.append(eachVer["ver"])
            idx2Ver[eachVer["idx"]] = eachVer["ver"]

    return allVerList, idx2Ver


def readWeigts(repoName):
    weightDict = {}

    with open(weightPath + repoName + "_weights", 'r', encoding="UTF-8") as fp:
        weightDict = json.load(fp)

    return weightDict


def detector(inputDict, inputRepo):
    inputDict = {k: set(v) for k, v in inputDict.items()}  # Change to set for faster lookup
    componentDB = {}

    componentDB = readComponentDB()

    fres = open(resultPath + "result_" + os.path.basename(inputRepo), 'w')
    aveFuncs = getAveFuncs()

    for OSS in componentDB:
        commonFunc = set()  # Change to set for faster lookup
        repoName = OSS.split('_sig')[0]
        totOSSFuncs = float(aveFuncs[repoName])
        if totOSSFuncs == 0.0:
            continue
        comOSSFuncs = 0.0
        for hashval in componentDB[OSS]:
            hashval_pre = re.split(r'\|', hashval)
            if hashval_pre[0] in inputDict:
                commonFunc.add(hashval)
                comOSSFuncs += 1.0

        #print(repoName, comOSSFuncs, commonFunc, totOSSFuncs, comOSSFuncs / totOSSFuncs)
        #print("\n")

        if (comOSSFuncs / totOSSFuncs) >= theta:
            """
            verPredictDict = {}
            allVerList, idx2Ver = readAllVers(repoName)

            for eachVersion in allVerList:
                verPredictDict[eachVersion] = 0.0

            weightDict = readWeigts(repoName)

            with open(initialDBPath + OSS, 'r', encoding="UTF-8") as fi:
                jsonLst = json.load(fi)
                for eachHash in jsonLst:
                    hashval = eachHash["hash"]
                    verlist = eachHash["vers"]

                    if hashval in commonFunc:
                        for addedVer in verlist:
                            verPredictDict[idx2Ver[addedVer]] += weightDict[hashval]

            sortedByWeight = sorted(verPredictDict.items(), key=lambda x: x[1], reverse=True)
            predictedVer = sortedByWeight[0][0]

            predictOSSDict = {}
            with open(repoFuncPath + repoName + '/fuzzy_' + predictedVer + '.hidx', 'r', encoding="UTF-8") as fo:
                body = ''.join(fo.readlines()).strip()
                for eachLine in body.split('\n')[1:]:
                    ohash = eachLine.split('\t')[0]
                    opath = eachLine.split('\t')[1]

                    predictOSSDict[ohash] = opath.split('\t')

            used = 0
            unused = 0
            modified = 0
            strChange = False

            for ohash in predictOSSDict:
                flag = 0

                if ohash in inputDict:
                    used += 1

                    nflag = 0
                    for opath in predictOSSDict[ohash]:
                        for tpath in inputDict[ohash]:
                            if opath in tpath:
                                nflag = 1
                    if nflag == 0:
                        strChange = True

                    flag = 1

                else:
                    for thash in inputDict:
                        # score = tlsh.diff(tlsh.hash(ohash.encode()), tlsh.hash(thash.encode()))
                        score = Simhash(ohash).distance(Simhash(thash))
                        if int(score) <= 10:  # 10
                            modified += 1

                            nflag = 0
                            for opath in predictOSSDict[ohash]:
                                for tpath in inputDict[thash]:
                                    if opath in tpath:
                                        nflag = 1
                            if nflag == 0:
                                strChange = True

                            flag = 1

                            break  # TODO: Suppose just only one function meet.
                if flag == 0:
                    unused += 1

            fres.write('\t'.join(
                [inputRepo, repoName, predictedVer, str(used), str(unused), str(modified), str(strChange)]) + '\n')
                """
            fres.write('\t'.join
                       ([repoName, str(comOSSFuncs), ', '.join(map(str, commonFunc)),
                         str(totOSSFuncs), str(comOSSFuncs / totOSSFuncs)]) + '\n')
    fres.close()


def main(inputPath, inputRepo):
    resDict, fileCnt = extract_symbols_and_data(inputPath)

    detector(resDict, inputRepo)


""" EXECUTE """
if __name__ == "__main__":

    testmode = 1

    if testmode:
        inputPath = currentPath + "/crown/crown_release"
    else:
        inputPath = sys.argv[1]

    inputRepo = inputPath.split('/')[-1]

    main(inputPath, inputRepo)
