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

currentPath = os.path.dirname(os.path.realpath(__file__))
gitCloneURLS = currentPath + "/sample_1-100"  # Please change to the correct file (the "sample" file contains only 10 git-clone urls)
clonePath = currentPath + "/repo_src/"  # Default path
tagDatePath = currentPath + "/repo_date/"  # Default path
resultPath = currentPath + "/repo_functions/"  # Default path
ctagsPath = "/usr/bin/ctags"  # Ctags binary path (please specify your own ctags path)

# Generate directories`
shouldMake = [clonePath, tagDatePath, resultPath]
for eachRepo in shouldMake:
    if not os.path.isdir(eachRepo):
        os.mkdir(eachRepo)

def normalize(string):
    # Code for normalizing the input string.
    # LF and TAB literals, curly braces, and spaces are removed,
    # and all characters are lowercased.
    # ref: https://github.com/squizz617/vuddy
    return ''.join(string.replace('\n', '').replace('\r', '').replace('\t', '').replace('{', '').replace('}', '').split(
        ' ')).lower()

def hashing(repoPath):
    possible = (".c", ".cc", ".cpp")
    fileCnt = 0
    lineCnt = 0
    featCnt = 0
    resDict = {}

    for path, dir, files in os.walk(repoPath):
        for file in files:
            filePath = os.path.join(path, file)

            if file.endswith(possible):
                try:
                    ctags_output = subprocess.check_output(
                        f'{ctagsPath} -f - --kinds-C=* --fields=* "{filePath}"',
                        stderr=subprocess.STDOUT,
                        shell=True
                    ).decode()

                    f = open(filePath, 'r', encoding="UTF-8")
                    lines = f.readlines()

                    fileCnt += 1
                    lineCnt += len(lines)

                    for line_number, line in enumerate(lines):
                        # Extract string literals
                        string_literals = re.findall(r'"([^"]*)"', line)
                        for string_literal in string_literals:
                            string_literal = normalize(string_literal)
                            resDict[f"String_{line_number + 1}"] = {'type': 'string', 'file': filePath,
                                                                    'value': string_literal}

                        # Extract array values
                        array_values = re.findall(r'=\s*{\s*([^}]*)\s*}', line)
                        for array_value in array_values:
                            array_value = normalize(array_value)
                            resDict[f"Array_{line_number + 1}"] = {'type': 'array', 'file': filePath,
                                                                   'value': array_value}

                        # Extract enum values
                        enum_values = re.findall(r'enum\s+\w+\s*{\s*([^}]*)\s*}', line)
                        for enum_value in enum_values:
                            enum_value = normalize(enum_value)
                            resDict[f"Enum_{line_number + 1}"] = {'type': 'enum', 'file': filePath,
                                                                  'value': enum_value}

                    for line in ctags_output.split('\n'):
                        fields = line.split('\t')
                        if len(fields) < 4:
                            continue

                        tag, filepath, line_number, kind = None, None, None, None

                        for field in fields:
                            if field.startswith("kind:"):
                                kind = field.split(":")[1]
                            elif field.startswith("line:"):
                                line_number = int(field.split(":")[1])

                        filepath = fields[1]

                        tag = normalize(fields[0])  # The first field is usually the tag name

                        if None in [tag, filepath, line_number, kind]:
                            continue

                        if kind == 'variable':  # Global variables
                            variable_line = lines[line_number - 1].strip()
                            variable_value = re.search(r'=\s*(.*);', variable_line)
                            if variable_value:
                                value = normalize(variable_value.group(1))
                            else:
                                value = None
                            resDict[tag] = {'type': 'variable', 'file': filepath, 'value': value}

                        elif kind == 'enumerator':  # Enumeration names
                            enum_line = lines[line_number - 1].strip()
                            enum_value = re.search(r'=\s*(\w+)', enum_line)
                            if enum_value:
                                value = normalize(enum_value.group(1))
                            else:
                                value = None
                            resDict[tag] = {'type': 'enum', 'file': filepath, 'value': value}

                        elif kind == 'function':  # Functions
                            resDict[tag] = {'type': 'function', 'file': filepath}

                except subprocess.CalledProcessError as e:
                    print("Parser Error:", e)
                    continue
                except Exception as e:
                    print("Subprocess failed", e)
                    continue

    return resDict, fileCnt, featCnt, lineCnt


def indexing(resDict, title, filePath):
    fres = open(filePath, 'w')
    fres.write(title + '\n')

    for tag in resDict:
        line = f"{tag}\t{resDict[tag]['type']}"
        if 'value' in resDict[tag]:
            line += f"\t{resDict[tag]['value']}"
        line += f"\t{resDict[tag]['file']}"
        fres.write(line + '\n')

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
                featCnt = 0
                lineCnt = 0

                if tagResult == "":
                    # No tags, only master repo

                    resDict, fileCnt, featCnt, lineCnt = hashing(clonePath + repoName)
                    if len(resDict) > 0:
                        if not os.path.isdir(resultPath + repoName):
                            os.mkdir(resultPath + repoName)
                        title = '\t'.join([repoName, str(fileCnt), str(featCnt), str(lineCnt)])
                        resultFilePath = resultPath + repoName + '/fuzzy_' + repoName + '.hidx'  # Default file name: "fuzzy_OSSname.hidx"

                        indexing(resDict, title, resultFilePath)

                else:
                    for tag in str(tagResult).split('\n'):
                        # Generate function hashes for each tag (version)

                        checkoutCommand = subprocess.check_output("git checkout -f " + tag, stderr=subprocess.STDOUT,
                                                                  shell=True)
                        resDict, fileCnt, featCnt, lineCnt = hashing(clonePath + repoName)

                        if len(resDict) > 0:
                            if not os.path.isdir(resultPath + repoName):
                                os.mkdir(resultPath + repoName)
                            title = '\t'.join([repoName, str(fileCnt), str(featCnt), str(lineCnt)])
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