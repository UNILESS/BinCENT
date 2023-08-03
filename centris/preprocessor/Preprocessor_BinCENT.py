"""
Preprocessor.
Author:		Seunghoon Woo (seunghoonwoo@korea.ac.kr)
Modified: 	December 16, 2020.
"""

import os
import sys
import re
import shutil
import json
import math

"""GLOBALS"""
currentPath = os.path.dirname(os.path.realpath(__file__))
separator = "#@#"
sep_len = len(separator)
# So far, do not change #

theta = 0.1  # Default value (0.1)
tagDatePath = "C:\\Users\\sunup\\PycharmProjects\\BinCENT\\centris\\osscollector\\repo_date"  # Default path
resultPath = "C:\\Users\\sunup\\PycharmProjects\\BinCENT\\centris\\osscollector\\repo_functions\\"  # Default path
verIDXpath = currentPath + "/verIDX/"  # Default path
initialDBPath = currentPath + "/initialSigs/"  # Default path
finalDBPath = currentPath + "/componentDB/"  # Default path
metaPath = currentPath + "/metaInfos/"  # Default path
weightPath = metaPath + "/weights/"
funcDatePath = currentPath + "/funcDate/"  # Default path

# Generate directories
shouldMake = [verIDXpath, initialDBPath, finalDBPath, metaPath, funcDatePath, weightPath]
for eachRepo in shouldMake:
    if not os.path.isdir(eachRepo):
        os.mkdir(eachRepo)

funcDateDict = {}


def extractVerDate(repoName):
    # For extracting version (tag) date

    verDateDict = {}
    if os.path.isfile(os.path.join(tagDatePath, repoName)):
        with open(os.path.join(tagDatePath, repoName), 'r', encoding="UTF-8") as fp:
            lines = [l.strip('\n\r') for l in fp.readlines()]
            for eachLine in lines:
                versionList = []
                if "tag:" in eachLine:
                    date = eachLine[0:10]

                    if "," in eachLine:
                        verList = [x for x in eachLine.split("tag: ")]
                        for val in verList[1:]:
                            if ',' in val:
                                versionList.append(val.split(',')[0])
                            elif ')' in val:
                                versionList.append(val.split(')')[0])
                    else:
                        versionList = [(eachLine.split('tag: ')[1][:-1])]

                    for eachVersion in versionList:
                        verDateDict[eachVersion] = date

    return verDateDict


def redundancyElimination():
    for repoName in os.listdir(resultPath):
        print(repoName)

        funcDateDict = {}
        tempDateDict = {}
        verDateDict = extractVerDate(repoName)

        # if os.path.isfile(os.path.join(initialDBPath, repoName + "_sig")):
        # 	continue
        ## For skipping already generated Sigs

        verTempLst = []
        signature = {}
        verDict = {}
        idx = 0

        for eachVersion in os.listdir(os.path.join(resultPath, repoName)):
            versionName = eachVersion.split("fuzzy_")[1].replace(".hidx", "")
            if versionName == '' or versionName == " ":
                continue
            verTempLst.append(versionName)
        verTempLst.sort()

        try:
            for versionName in verTempLst:
                with open(os.path.join(resultPath, repoName, ("fuzzy_" + versionName + ".hidx")), 'r',
                          encoding="UTF-8") as fp:
                    verDict[versionName] = idx
                    idx += 1
                    body = ''.join(fp.readlines()).strip()
                    for eachLine in body.split('\n')[1:-1]:
                        if eachLine == '' or eachLine == ' ':
                            continue

                        hashval = eachLine.split('\t')[0]
                        if hashval not in signature:
                            signature[hashval] = []
                            tempDateDict[hashval] = []
                        signature[hashval].append(str(idx - 1))

                        if versionName in verDateDict:
                            tempDateDict[hashval].append(verDateDict[versionName])
                        else:
                            tempDateDict[hashval].append("NODATE")

        except Exception as e:
            print("Parsing error: ", e)
            continue

        # For storing function birthdate
        for hashval in tempDateDict:
            tempDateDict[hashval].sort()
            funcDateDict[hashval] = tempDateDict[hashval][0]

        fdate = open(funcDatePath + repoName + "_funcdate", 'w')
        for hashval in funcDateDict:
            fdate.write(hashval + '\t' + funcDateDict[hashval] + '\n')
        fdate.close()

        # For storing version indexes
        fidx = open(verIDXpath + repoName + "_idx", 'w')
        saveJson = []

        for verName in verTempLst:
            temp = {}
            temp["ver"] = verName
            temp["idx"] = str(verDict[verName])
            saveJson.append(temp)

        fidx.write(json.dumps(saveJson))
        fidx.close()

        # For storing OSS signatures
        f = open(initialDBPath + repoName + "_sig", 'w')

        saveJson = []
        for hashval in signature:
            temp = {}
            temp["hash"] = hashval
            temp["vers"] = signature[hashval]
            saveJson.append(temp)
        f.write(json.dumps(saveJson))
        f.close()


def saveMetaInfos():
    aveFuncJson = {}
    allFuncJson = {}
    uniqueJson = []
    unique = {}

    fave = open(metaPath + "aveFuncs", 'w')
    fall = open(metaPath + "allFuncs", 'w')
    funi = open(metaPath + "uniqueFuncs", 'w')

    for OSS in os.listdir(initialDBPath):
        weightJson = {}
        repoName = OSS.replace("_sig", "")
        totFuncs = 0
        totVers = len(os.listdir(resultPath + repoName))

        if totVers == 0:
            continue

        fwei = open(weightPath + "/" + repoName + "_weights", 'w')

        with open(initialDBPath + OSS, 'r', encoding="UTF-8") as fs:
            jsonStr = json.load(fs)
            totFuncs = len(jsonStr)

            for eachJson in jsonStr:
                hashval = eachJson['hash']
                verlst = eachJson['vers']

                if hashval not in unique:
                    unique[hashval] = []

                unique[hashval].append(repoName)
                weightJson[hashval] = math.log(float(totVers) / float(len(verlst)))

        aveFuncJson[repoName] = int(totFuncs / totVers)
        allFuncJson[repoName] = int(totFuncs)

        fwei.write(json.dumps(weightJson))
        fwei.close()

    for funcHash in unique:
        temp = {}
        temp["hash"] = funcHash
        temp["OSS"] = unique[funcHash]
        uniqueJson.append(temp)

    fave.write(json.dumps(aveFuncJson))
    fall.write(json.dumps(allFuncJson))
    funi.write(json.dumps(uniqueJson))

    fave.close()
    fall.close()
    funi.close()


def readVerDate(verDateDict, repoName):
    verDateDict[repoName] = {}

    if os.path.isfile(funcDatePath + repoName + "_funcdate"):
        with open(funcDatePath + repoName + "_funcdate", 'r', encoding="UTF-8") as fp:
            body = ''.join(fp.readlines()).strip()
            for eachLine in body.split('\n'):
                hashval = eachLine.split('\t')[0]
                parts = eachLine.split('\t')
                if len(parts) > 1:
                    date = parts[1]
                else:
                    date = "NODATE"  # or some default value
                verDateDict[repoName][hashval] = date
    return verDateDict


def getAveFuncs():
    aveFuncs = {}
    with open(metaPath + "aveFuncs", 'r', encoding="UTF-8") as fp:
        aveFuncs = json.load(fp)
    return aveFuncs


def codeSegmentation():
    for repoName in os.listdir(initialDBPath):
        print(repoName)

        tempDateDict = {}
        if os.path.isfile(os.path.join(finalDBPath, repoName + "_sig")):
            continue

        funcDateDict = {}
        if os.path.isfile(os.path.join(funcDatePath, repoName + "_funcdate")):
            with open(os.path.join(funcDatePath, repoName + "_funcdate"), 'r', encoding="UTF-8") as fp:
                lines = [l.strip('\n\r') for l in fp.readlines()]
                for eachLine in lines:
                    if eachLine == '' or eachLine == ' ':
                        continue
                    hashval, date = eachLine.split('\t')
                    funcDateDict[hashval] = date

        signature = {}
        if os.path.isfile(os.path.join(initialDBPath, repoName + "_sig")):
            with open(os.path.join(initialDBPath, repoName + "_sig"), 'r', encoding="UTF-8") as fp:
                lines = [l.strip('\n\r') for l in fp.readlines()]
                for eachLine in lines:
                    if eachLine == '' or eachLine == ' ':
                        continue
                    components = eachLine.split('\t')
                    hashval = components[0]
                    versions = components[1:]
                    signature[hashval] = versions

        # For storing function hash signatures
        sig = open(finalDBPath + repoName + "_sig", 'w')
        for hashval in signature:
            sig.write(hashval + '\t' + funcDateDict[hashval] + '\t' + '\t'.join(signature[hashval]) + '\n')
        sig.close()

def main():
    redundancyElimination()
    saveMetaInfos()
    codeSegmentation()


""" EXECUTE """
if __name__ == "__main__":
    main()