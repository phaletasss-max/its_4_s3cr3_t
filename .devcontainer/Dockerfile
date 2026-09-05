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
    python3-venv \
    openssh-client \
    netcat-openbsd \
    nmap \
    dnsutils \
    iproute2 \
    iputils-ping \
    traceroute \
    tcpdump \
    file \
    binutils \
    unzip \
    jq \
    && apt clean \
    && rm -rf /var/lib/apt/lists/*
