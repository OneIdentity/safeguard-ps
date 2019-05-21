# This shouldn't be run directly

print_usage()
{
    >&2 cat <<EOF
USAGE: run-docker.sh [imagetype] [-h]

  -h  Show help and exit

imagetype should be one of the following:

  'ubuntu', 'ubuntu18.04', 'ubuntu16.04'
  'centos', 'centos7'
  'alpine', 'alpine3.8'
  'opensuse', 'opensuse42.3'
  'fedora', 'fedora28'

EOF
    kill -s TERM $TOP_PID
}

get_safeguard_dockerfile()
{
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
    echo "$DockerFile"
}

