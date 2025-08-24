#!/bin/bash
function rotate() {
  fname="$1"
  if [ -z "$fname" ]; then
    echo "Usage: $0 <fname>"
    exit 1
  fi
  mv "$1" "$1.orig"
}

function build_img() {
  [[ ! -f Dockerfile ]] && exit 1

  docker build -t ebpf-playground:0.1 .
}
