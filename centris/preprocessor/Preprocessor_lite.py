import os
import sys
import re
import shutil
import json
import math
import traceback
import numpy
import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer

"""GLOBALS"""
currentPath = os.path.dirname(os.path.realpath(__file__))
separator = "#@#"
sep_len = len(separator)
# So far, do not change #

theta = 0.1  # Default value (0.1)
tagDatePath = "/home/jeongwoo/PycharmProjects/BinCENT_2nd/centris/osscollector/repo_date"  # Default path
resultPath = "/home/jeongwoo/PycharmProjects/BinCENT_2nd/centris/osscollector/repo_functions/"  # Default path
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


def calculate_tfidf(corpus):
    if not corpus:
        print("Warning: Empty corpus. Returning empty TF-IDF scores.")
        return {}

    vectorizer = TfidfVectorizer()
    X = vectorizer.fit_transform(corpus)
    feature_names = vectorizer.get_feature_names_out()
    doc = 0  # Assuming you want the TF-IDF scores for the first document in the corpus
    feature_index = X[doc, :].nonzero()[1]
    tfidf_scores = {feature_names[i]: X[doc, i] for i in feature_index}

    return tfidf_scores

def calculate_threshold(tfidf_scores):
    scores = list(tfidf_scores.values())
    mean_score = np.mean(scores)
    std_dev = np.std(scores)
    threshold = mean_score + std_dev  # You can adjust this formula as needed
    return threshold

global_feature_dates = {}

def redundancyElimination():
    global global_feature_dates
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

                        fields = eachLine.split('\t')
                        if len(fields) < 3:  # Ensure there are enough fields
                            continue

                        tag_type = fields[1]
                        value = fields[2]

                        if tag_type == "variable":
                            # For the tag name
                            hashval_tag = fields[0]
                            if hashval_tag not in signature:
                                signature[hashval_tag] = []
                                tempDateDict[hashval_tag] = []
                            signature[hashval_tag].append(str(idx - 1))

                            # For the value
                            hashval_value = value
                            if hashval_value not in signature:
                                signature[hashval_value] = []
                                tempDateDict[hashval_value] = []
                            signature[hashval_value].append(str(idx - 1))

                        elif tag_type in ["array", "string", "enum"]:
                            hashval = value
                            if hashval not in signature:
                                signature[hashval] = []
                                tempDateDict[hashval] = []
                            signature[hashval].append(str(idx - 1))

                        else:
                            hashval = fields[0]
                            if hashval not in signature:
                                signature[hashval] = []
                                tempDateDict[hashval] = []
                            signature[hashval].append(str(idx - 1))


                        if versionName in verDateDict:
                            if hashval in tempDateDict:
                                tempDateDict[hashval].append(verDateDict[versionName])
                        else:
                            if hashval in tempDateDict:
                                tempDateDict[hashval].append("NODATE")

        except Exception as e:
            print("Parsing error: ", e)
            traceback.print_exc()
            continue

        tfidf_scores = calculate_tfidf(signature)
        threshold = calculate_threshold(tfidf_scores)

        # For storing function birthdate
        for hashval in tempDateDict:
            if hashval in tempDateDict and tempDateDict[hashval]:
                tempDateDict[hashval].sort()
                funcDateDict[hashval] = tempDateDict[hashval][0]

                # Update global_feature_dates
                if hashval not in global_feature_dates:
                    global_feature_dates[hashval] = {'date': funcDateDict[hashval], 'repo': repoName}
                else:
                    if funcDateDict[hashval] < global_feature_dates[hashval]['date']:
                        global_feature_dates[hashval] = {'date': funcDateDict[hashval], 'repo': repoName}

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
            if hashval in tfidf_scores and tfidf_scores[hashval] < threshold:  # Use the calculated threshold
                continue  # Skip this feature due to low TF-IDF score

            temp = {}
            temp["hash"] = hashval
            temp["vers"] = signature[hashval]
            saveJson.append(temp)
        f.write(json.dumps(saveJson))
        f.close()


def removeRedundantFeatures():
    global global_feature_dates
    for repoName in os.listdir(initialDBPath):
        to_remove = []
        with open(os.path.join(initialDBPath, repoName), 'r', encoding="UTF-8") as f:
            data = json.load(f)

        for feature in data:
            hashval = feature['hash']
            feature_type = feature.get('type', None)
            feature_value = feature.get('value', None)

            unique_key = f"{hashval}_{feature_value}"

            if unique_key in global_feature_dates:
                if global_feature_dates[unique_key]['repo'] != repoName.replace("_sig", ""):
                    to_remove.append(feature)

        for feature in to_remove:
            data.remove(feature)

        with open(os.path.join(initialDBPath, repoName), 'w', encoding="UTF-8") as f:
            json.dump(data, f)

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
    aveFuncs = getAveFuncs()

    # For printing process

    l = 1
    tot = len(os.listdir(initialDBPath))
    print('[+] Read OSS signatures..')
    OSSList = os.listdir(initialDBPath)

    versSignatures = {}
    dateSignatures = {}
    uniqueFuncs = {}

    with open(metaPath + "uniqueFuncs", 'r', encoding="UTF-8") as fp:
        jsonStr = json.load(fp)
        for eachVal in jsonStr:
            hashval = eachVal['hash']
            uniqueFuncs[hashval] = eachVal['OSS']

    verDateDict = {}

    for S_sig in OSSList:
        print(l, '/', tot, S_sig)

        S = S_sig.replace("_sig", "")
        l += 1

        possibleMembers = {}
        candiX = {}
        removedFuncs = []

        if S not in verDateDict:
            verDateDict = readVerDate(verDateDict, S)

        with open(initialDBPath + S_sig, 'r', encoding="UTF-8") as fs:
            jsonStr = json.load(fs)
            if len(jsonStr) == 0:
                continue
            else:
                temp = {}
                for eachVal in jsonStr:
                    hashval = eachVal['hash']

                    for OSS in uniqueFuncs[hashval]:
                        if OSS == S:
                            continue

                        if OSS not in candiX:
                            temp[OSS] = []
                            candiX[OSS] = 0

                        if OSS not in verDateDict:
                            verDateDict = readVerDate(verDateDict, OSS)

                        try:
                            if hashval not in verDateDict[S]:
                                continue

                            if verDateDict[S][hashval] == "NODATE" or verDateDict[OSS][hashval] == "NODATE":
                                candiX[OSS] += 1
                                temp[OSS].append(hashval)

                            elif verDateDict[OSS][hashval] <= verDateDict[S][hashval]:
                                candiX[OSS] += 1
                                temp[OSS].append(hashval)
                        except:
                            pass

                for X in candiX:
                    if aveFuncs[X] == 0:
                        continue

                    elif len(verDateDict[X]) == 0:
                        continue

                    elif (float(candiX[X]) / float(aveFuncs[X])) >= theta:
                        if S not in possibleMembers:
                            possibleMembers[S] = []

                        possibleMembers[S].append(X)
                        removedFuncs.extend(temp[X])

                if S not in possibleMembers:
                    shutil.copy(os.path.join(initialDBPath, S) + "_sig", os.path.join(finalDBPath, S) + "_sig")

                else:
                    removedFuncs = set(removedFuncs)
                    saveJson = []
                    fres = open(os.path.join(finalDBPath, S) + "_sig", 'w')

                    for eachVal in jsonStr:
                        temp = {}
                        hashval = eachVal['hash']

                        if hashval not in removedFuncs:
                            versLst = eachVal['vers']
                            temp["hash"] = hashval
                            temp["vers"] = versLst
                            saveJson.append(temp)

                    fres.write(json.dumps(saveJson))
                    fres.close()


def main():
    redundancyElimination()
    saveMetaInfos()
    removeRedundantFeatures()
    codeSegmentation()


""" EXECUTE """
if __name__ == "__main__":
    main()