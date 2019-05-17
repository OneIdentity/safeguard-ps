#!/bin/bash

print_usage()
{
    cat <<EOF
USAGE: run-docker.sh [imagetype] [-h]

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

case $1 in
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
ImageType=$1

echo "Rebuilding the image: safeguard-ps:$ImageType ..."
$ScriptDir/build-docker.sh $ImageType

echo "Running the image: safeguard-ps:$ImageType ..."
docker run -it "safeguard-ps:$ImageType"
