#!/bin/bash

print_usage()
{
    cat <<EOF
USAGE: build-docker.sh [imagetype] [-h]

  -h  Show help and exit

imagetype should be one of the following: 

  'ubuntu', 'ubuntu18.04', 'ubuntu16.04'
  'centos', 'centos7'
  'alpine', 'alpine3.8'
  'opensuse', 'opensuse42.3'
  'fedora', 'fedora28'

EOF
    exit 0
}

if [ -z "$1" ]; then
    ImageType=alpine
else
    ImageType=$1
fi

case $ImageType in
ubuntu | ubuntu18.04)
    DockerFile="Dockerfile_ubuntu18.04"
    ;;
ubuntu16.04)
    DockerFile="Dockerfile_ubuntu16.04"
    ;;
centos | centos7)
    DockerFile="Dockerfile_centos7"
    ;;
alpine | alpine3.8)
    DockerFile="Dockerfile_alpine3.8"
    ;;
opensuse | opensuse42.3)
    DockerFile="Dockerfile_opensuse42.3"
    ;;
fedora | fedora28)
    DockerFile="Dockerfile_fedora28"
    ;;
*)
    print_usage
    ;;
esac

ScriptDir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

if [ ! -z "$(docker images -q safeguard-ps:$ImageType)" ]; then
    echo "Cleaning up the old image: safeguard-ps:$ImageType ..."
    docker rmi --force "safeguard-ps:$ImageType"
fi
echo "Building a new image: safeguard-ps:$ImageType ..."
docker build --no-cache -t "safeguard-ps:$ImageType" -f $DockerFile $ScriptDir
