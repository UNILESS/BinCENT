"""
Dataset Collection Tool.
Author:		Seunghoon Woo (seunghoonwoo@korea.ac.kr)
Modified: 	December 16, 2020.
"""

import os
import sys
import subprocess
import re
import traceback

"""GLOBALS"""

currentPath = os.getcwd()
gitCloneURLS = currentPath + "/sample"  # Please change to the correct file (the "sample" file contains only 10 git-clone urls)
clonePath = currentPath + "/repo_src/"  # Default path
tagDatePath = currentPath + "/repo_date/"  # Default path
resultPath = currentPath + "/repo_functions/"  # Default path
ctagsPath = "/usr/bin/ctags"  # Ctags binary path (please specify your own ctags path)

# Generate directories
shouldMake = [clonePath, tagDatePath, resultPath]
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


def extract_names_and_counts(repoPath):
    possible = (".c", ".cc", ".cpp")
    names = []

    fileCnt = 0
    funcCnt = 0
    lineCnt = 0

    for path, dir, files in os.walk(repoPath):
        for file in files:
            filePath = os.path.join(path, file)

            if file.endswith(possible):
                try:
                    tagList = subprocess.check_output(
                        ctagsPath + ' -f - --kinds-C=* --fields=neKSt "' + filePath + '"', stderr=subprocess.STDOUT,
                        shell=True).decode()

                    f = open(filePath, 'r', encoding="UTF-8")
                    lines = f.readlines()

                    allTags = str(tagList).split('\n')
                    func = re.compile(r'(function)')
                    variable = re.compile(r'(variable)')
                    array = re.compile(r'(array)')

                    fileCnt += 1

                    for i in allTags:
                        elemList = re.sub(r'[\t\s ]{2,}', '', i)
                        elemList = elemList.split('\t')

                        if i != '' and len(elemList) >= 8:
                            if func.fullmatch(elemList[3]):
                                names.append(elemList[0])
                                funcCnt += 1
                            elif variable.fullmatch(elemList[3]):
                                names.append(elemList[0])
                            elif array.fullmatch(elemList[3]):
                                names.append(elemList[0])

                    lineCnt += len(lines)

                except subprocess.CalledProcessError as e:
                    print("Parser Error:", e)
                    traceback.print_exc()
                    continue
                except Exception as e:
                    print("Subprocess failed", e)
                    traceback.print_exc()
                    continue

    return names, fileCnt, funcCnt, lineCnt



def indexing(resDict, title, filePath):
    # For indexing each OSS

    fres = open(filePath, 'w')
    fres.write(title + '\n')

    for hashval in resDict:
        if hashval == '' or hashval == ' ':
            continue

        fres.write(hashval)

        for funcPath in resDict[hashval]:
            fres.write('\t' + funcPath)
        fres.write('\n')

    fres.close()


def main():
    with open(gitCloneURLS, 'r', encoding="UTF-8") as fp:
        funcDateDict = {}
        lines = [l.strip('\n\r') for l in fp.readlines()]

        for eachUrl in lines:
            os.chdir(currentPath)
            repoName = eachUrl.split("github.com/")[1].replace(".git", "").replace("/",
                                                                                   "@@")  # Replace '/' -> '@@' for convenience
            print("[+] Processing", repoName)

            try:
                cloneCommand = eachUrl + ' ' + clonePath + repoName
                cloneResult = subprocess.check_output(cloneCommand, stderr=subprocess.STDOUT, shell=True).decode()

                os.chdir(clonePath + repoName)

                dateCommand = 'git log --tags --simplify-by-decoration --pretty="format:%ai %d"'  # For storing tag dates
                dateResult = subprocess.check_output(dateCommand, stderr=subprocess.STDOUT, shell=True).decode()
                tagDateFile = open(tagDatePath + repoName, 'w')
                tagDateFile.write(str(dateResult))
                tagDateFile.close()

                tagCommand = "git tag"
                tagResult = subprocess.check_output(tagCommand, stderr=subprocess.STDOUT, shell=True).decode()

                resDict = {}
                fileCnt = 0
                funcCnt = 0
                lineCnt = 0

                if tagResult == "":
                    # No tags, only master repo

                    resDict, fileCnt, funcCnt, lineCnt = extract_names_and_counts(clonePath + repoName)
                    if len(resDict) > 0:
                        if not os.path.isdir(resultPath + repoName):
                            os.mkdir(resultPath + repoName)
                        title = '\t'.join([repoName, str(fileCnt), str(funcCnt), str(lineCnt)])
                        resultFilePath = resultPath + repoName + '/fuzzy_' + repoName + '.hidx'  # Default file name: "fuzzy_OSSname.hidx"

                        indexing(resDict, title, resultFilePath)

                else:
                    for tag in str(tagResult).split('\n'):
                        # Generate function hashes for each tag (version)

                        checkoutCommand = subprocess.check_output("git checkout -f " + tag, stderr=subprocess.STDOUT,
                                                                  shell=True)
                        resDict, fileCnt, funcCnt, lineCnt = extract_names_and_counts(clonePath + repoName)

                        if len(resDict) > 0:
                            if not os.path.isdir(resultPath + repoName):
                                os.mkdir(resultPath + repoName)
                            title = '\t'.join([repoName, str(fileCnt), str(funcCnt), str(lineCnt)])
                            resultFilePath = resultPath + repoName + '/fuzzy_' + tag + '.hidx'

                            indexing(resDict, title, resultFilePath)


            except subprocess.CalledProcessError as e:
                print("Parser Error:", e)
                continue
            except Exception as e:
                print("Subprocess failed", e)
                continue


""" EXECUTE """
if __name__ == "__main__":
    main()