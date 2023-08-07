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

import clang.cindex

"""GLOBALS"""

currentPath = os.path.dirname(os.path.realpath(__file__))
gitCloneURLS = currentPath + "/sample_origin"  # Please change to the correct file (the "sample" file contains only 10 git-clone urls)
clonePath = currentPath + "/repo_src/"  # Default path
tagDatePath = currentPath + "/repo_date/"  # Default path
resultPath = currentPath + "/repo_functions/"  # Default path
ctagsPath = "/opt/homebrew/bin/ctags"  # Ctags binary path (please specify your own ctags path)

clang.cindex.Config.set_library_path('/opt/homebrew/Cellar/llvm/16.0.6/lib')  # Adjust this path to your system's libclang library


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


def clean_string_literal(string):
    # 개행 문자와 특수 문자 제거
    cleaned_string = re.sub(r'[^a-zA-Z0-9]', '', string)
    return cleaned_string

def extract_names_and_counts_with_libclang(repoPath):

    fileCnt = 0
    names = {}

    for path, _, files in os.walk(repoPath):
        for file in files:
            filePath = os.path.join(path, file)
            if file.endswith(('.c', '.cc', '.cpp')):
                index = clang.cindex.Index.create()
                translation_unit = index.parse(filePath)
                for cursor in translation_unit.cursor.walk_preorder():
                    if cursor.kind == clang.cindex.CursorKind.TRANSLATION_UNIT:
                        continue
                    name = cursor.spelling
                    kind = cursor.kind.name

                    # STRING_LITERAL 처리
                    if cursor.kind == clang.cindex.CursorKind.STRING_LITERAL:
                        name = clean_string_literal(name)

                    name_kind_key = f"{name}|**|{kind}"
                    if name_kind_key not in names:
                        names[name_kind_key] = []
                    names[name_kind_key].append(filePath)

                fileCnt += 1

    return names, fileCnt


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

                if tagResult == "":
                    # No tags, only master repo

                    resDict, fileCnt = extract_names_and_counts_with_libclang(clonePath + repoName)
                    if len(resDict) > 0:
                        if not os.path.isdir(resultPath + repoName):
                            os.mkdir(resultPath + repoName)
                        title = '\t'.join([repoName, str(fileCnt)])
                        resultFilePath = resultPath + repoName + '/fuzzy_' + repoName + '.hidx'  # Default file name: "fuzzy_OSSname.hidx"

                        indexing(resDict, title, resultFilePath)

                else:
                    for tag in str(tagResult).split('\n'):
                        # Generate function hashes for each tag (version)

                        checkoutCommand = subprocess.check_output("git checkout -f " + tag, stderr=subprocess.STDOUT,
                                                                  shell=True)
                        resDict, fileCnt = extract_names_and_counts_with_libclang(clonePath + repoName)

                        if len(resDict) > 0:
                            if not os.path.isdir(resultPath + repoName):
                                os.mkdir(resultPath + repoName)
                            title = '\t'.join([repoName, str(fileCnt)])
                            resultFilePath = resultPath + repoName + '/fuzzy_' + tag + '.hidx'

                            indexing(resDict, title, resultFilePath)


            except subprocess.CalledProcessError as e:
                print("Parser Error:", e)
                traceback.print_exc()
                continue
            except Exception as e:
                print("Subprocess failed", e)
                traceback.print_exc()
                continue


""" EXECUTE """
if __name__ == "__main__":
    main()