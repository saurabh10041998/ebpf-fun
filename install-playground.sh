#!/bin/bash
docker container run -it --rm \
  --privileged \
  --cap-add=SYS_ADMIN \
  --cap-add=SYS_RESOURCE \
  --cap-add=SYS_PTRACE \
  --cap-add=BPF \
  --security-opt seccomp=unconfined \
  -v "$PWD":/workspace \
  -v /sys:/sys \
  -w /workspace \
  -v /lib/modules:/lib/modules \
  -v /usr/src:/usr/src \
  ebpf-playground:0.2

