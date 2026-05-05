# Copyright (c) 2026 One Identity LLC. All rights reserved.
# This shouldn't be run directly

print_usage()
{
    >&2 cat <<EOF
USAGE: run-docker.sh [imagetype] [-h]

  -h  Show help and exit

imagetype should be one of the following:

  'ubuntu', 'ubuntu-24.04',
  'azurelinux', 'azurelinux-3.0', 'mariner'
  'alpine', 'alpine-3.22'

EOF
    kill -s TERM $TOP_PID
}

get_safeguard_dockerfile()
{
    case $1 in
    ubuntu | ubuntu-24.04)
        DockerFile="Dockerfile_ubuntu"
        ;;
    alpine | alpine-3.22)
        DockerFile="Dockerfile_alpine"
        ;;
    azurelinux | azurelinux-3.0 | mariner)
        DockerFile="Dockerfile_azurelinux"
        ;;
    *)
        print_usage
        ;;
    esac
    echo "$DockerFile"
}
