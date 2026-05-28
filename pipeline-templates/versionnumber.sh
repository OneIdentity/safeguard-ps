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
    if ! echo "$tagName" | grep -qE '^v[0-9]+\.[0-9]+\.[0-9]+(\.[0-9]+)?$'; then
        echo "##[error]Tag '$tagName' does not match expected format v<major>.<minor>.<patch>[.<build>]"
        exit 1
    fi
    buildNumber=$(expr $buildId - 250000)
    tagVersion="${tagName#v}"
    segmentCount=$(echo "$tagVersion" | awk -F. '{print NF}')
    if [ "$segmentCount" -eq 3 ]; then
        versionString="${tagVersion}.${buildNumber}"
    else
        versionString="$tagVersion"
    fi
    prereleaseSuffix=""
    releaseTag="$tagName"
    echo "Tag build: VersionString = $versionString, ReleaseTag = $releaseTag"
else
    buildNumber=$(expr $buildId - 250000) # shrink shared build number appropriately
    echo "buildNumber = ${buildNumber}"
    versionString="${verNum}.${buildNumber}"
    prereleaseSuffix="pre${buildNumber}"
    releaseTag="dev/v${verNum}.${buildNumber}-${prereleaseSuffix}"
    echo "Dev build: VersionString = $versionString, PrereleaseSuffix = $prereleaseSuffix, ReleaseTag = $releaseTag"
fi

echo "##vso[task.setvariable variable=VersionString;]$versionString"
echo "##vso[task.setvariable variable=PrereleaseSuffix;]$prereleaseSuffix"
echo "##vso[task.setvariable variable=ReleaseTag;]$releaseTag"
