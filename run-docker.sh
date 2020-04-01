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

echo "Rebuilding the image: oneidentity/safeguard-ps:$ImageType ..."
$ScriptDir/build-docker.sh $ImageType

echo "Running the image: oneidentity/safeguard-ps:$ImageType ..."
docker run -it "oneidentity/safeguard-ps:$ImageType"

