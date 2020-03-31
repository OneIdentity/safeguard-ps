#!/bin/bash
trap "exit 1" TERM
export TOP_PID=$$

if [ -z "$1" ]; then
    ImageType=alpine
else
    ImageType=$1
fi

if [ ! -z "$2" ]; then
    Version="${2}-"
fi

ScriptDir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
. "$ScriptDir/docker/docker-include.sh"

DockerFile=`get_safeguard_dockerfile $ImageType`

if [ ! -z "$(docker images -q safeguard-ps:$Version$ImageType)" ]; then
    echo "Cleaning up the old image: safeguard-ps:$Version$ImageType ..."
    docker rmi --force "safeguard-ps:$Version$ImageType"
fi
echo "Building a new image: safeguard-ps:$Version$ImageType ..."
docker build --no-cache -t "safeguard-ps:$Version$ImageType" -f "docker/$DockerFile" $ScriptDir
