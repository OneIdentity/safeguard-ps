#!/bin/bash
# Copyright (c) 2026 One Identity LLC. All rights reserved.
if [ "$#" -lt 2 ]; then
    >&2 echo "This script requires at least 2 arguments -- verNum, buildId [tagName] [isTagBuild]"
    exit 1
fi
verNum=$1
buildId=$2
tagName=${3:-""}
isTagBuild=${4:-"False"}

echo "verNum = $verNum"
echo "buildId = $buildId"
echo "tagName = $tagName"
echo "isTagBuild = $isTagBuild"

if [ "$isTagBuild" = "True" ]; then
    if ! echo "$tagName" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+$'; then
        echo "##[error]Tag '$tagName' does not match expected format v<major>.<minor>.<patch>"
        exit 1
    fi
    versionString="${tagName#v}"
    prereleaseSuffix=""
    releaseTag="$tagName"
    echo "Tag build: VersionString = $versionString, ReleaseTag = $releaseTag"
else
    buildNumber=$(expr $buildId - 102500) # shrink shared build number appropriately
    echo "buildNumber = ${buildNumber}"
    versionString="$verNum.0"
    prereleaseSuffix="pre${buildNumber}"
    releaseTag="dev/v${verNum}.0-${prereleaseSuffix}"
    echo "Dev build: VersionString = $versionString, PrereleaseSuffix = $prereleaseSuffix, ReleaseTag = $releaseTag"
fi

echo "##vso[task.setvariable variable=VersionString;]$versionString"
echo "##vso[task.setvariable variable=PrereleaseSuffix;]$prereleaseSuffix"
echo "##vso[task.setvariable variable=ReleaseTag;]$releaseTag"
