FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt update && apt install -y \
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
    docker.io \
    && apt clean \
    && rm -rf /var/lib/apt/lists/*
