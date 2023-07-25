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

"""GLOBALS"""
currentPath = os.getcwd()
theta = 0.1
resultPath = currentPath + "/res/"
repoFuncPath = "C:\\Users\\sunup\\PycharmProjects\\BinCENT\\src\\osscollector\\repo_functions\\"
verIDXpath = "C:\\Users\\sunup\\PycharmProjects\\BinCENT\\src\\osscollector\\verIDX\\"
initialDBPath = "C:\\Users\\sunup\\PycharmProjects\\BinCENT\\src\\osscollector\\initialSigs\\"
finalDBPath = "C:\\Users\\sunup\\PycharmProjects\\BinCENT\\src\\osscollector\\componentDB\\"
metaPath = "C:\\Users\\sunup\\PycharmProjects\\BinCENT\\src\\osscollector\\metaInfos\\"
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


def hashing(repoPath):
    # This function is for extracting symbols from binary files
    fileCnt = 0
    resDict = {}

    for path, dir, files in os.walk(repoPath):
        for file in files:
            filePath = os.path.join(path, file)

            try:
                # Execute radare2 command to get symbols
                symbolList = subprocess.check_output(
                    'radare2 -c "isj" "' + filePath + '"', shell=True
                ).decode()

                symbols = json.loads(symbolList)  # as radare2 returns a json

                fileCnt += 1

                for symbol in symbols:
                    # Normalizing the symbol names
                    normalizedSymbol = normalize(symbol["name"])

                    storedPath = filePath.replace(repoPath, "")
                    if normalizedSymbol not in resDict:
                        resDict[normalizedSymbol] = []
                    resDict[normalizedSymbol].append(storedPath)

            except subprocess.CalledProcessError as e:
                print("Parser Error:", e)
                continue
            except Exception as e:
                print("Subprocess failed", e)
                continue

    return resDict, fileCnt


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
                componentDB[OSS].append(hashval)

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
    componentDB = {}

    componentDB = readComponentDB()

    fres = open(resultPath + "result_" + inputRepo, 'w')
    aveFuncs = getAveFuncs()

    for OSS in componentDB:
        commonFunc = []
        repoName = OSS.split('_sig')[0]
        totOSSFuncs = float(aveFuncs[repoName])
        if totOSSFuncs == 0.0:
            continue
        comOSSFuncs = 0.0
        for hashval in componentDB[OSS]:
            if hashval in inputDict:
                commonFunc.append(hashval)
                comOSSFuncs += 1.0

        if (comOSSFuncs / totOSSFuncs) >= theta:
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
                        score = tlsh.diffxlen(ohash, thash)
                        if int(score) <= 30:
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
    fres.close()


def main(inputPath, inputRepo):
    resDict, fileCnt = hashing(inputPath)

    detector(resDict, inputRepo)


""" EXECUTE """
if __name__ == "__main__":

    testmode = 1

    if testmode:
        inputPath = currentPath + "\\crown-development"
    else:
        inputPath = sys.argv[1]

    inputRepo = inputPath.split('/')[-1]

    main(inputPath, inputRepo)
