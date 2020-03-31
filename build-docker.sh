#!/bin/bash
trap "exit 1" TERM
export TOP_PID=$$

if [ -z "$1" ]; then
    ImageType=alpine
else
    ImageType=$1
fi

ScriptDir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
. "$ScriptDir/docker/docker-include.sh"

DockerFile=`get_safeguard_dockerfile $ImageType`

if [ ! -z "$(docker images -q safeguard-ps:$ImageType)" ]; then
    echo "Cleaning up the old image: safeguard-ps:$ImageType ..."
    docker rmi --force "safeguard-ps:$ImageType"
fi
echo "Building a new image: safeguard-ps:$ImageType ..."
docker build --no-cache -t "safeguard-ps:$ImageType" -f $DockerFile $ScriptDir

