#!/bin/bash
if [ "$#" -ne 2 ]; then
    >&2 echo "This script requires 2 arguments -- verNum, buildId"
    exit 1
fi
verNum=$1
buildId=$2

echo "verNum = $verNum"
echo "buildId = $buildId"

buildNumber=$(expr $buildId - 102500) # shrink shared build number appropriately
echo "buildNumber = ${buildNumber}"

versionString="$verNum.$buildNumber"
echo "VersionString = ${versionString}"

echo "##vso[task.setvariable variable=VersionString;]$versionString"
