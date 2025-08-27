FROM ubuntu:22.04

RUN : \
    && DEBIAN_FRONTEND=non-interactive \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        bpfcc-tools \
        bpftrace \
        clang \
        llvm
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
