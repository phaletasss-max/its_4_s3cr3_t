FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y \
    kali-linux-headless \
    git \
    curl \
    wget \
    nano \
    vim \
    python3 \
    python3-pip \
    nmap \
    netcat-openbsd \
    dnsutils \
    iproute2 \
    iputils-ping \
    traceroute \
    tcpdump \
    docker.io \
    && apt clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspaces
