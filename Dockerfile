# Virtual Browser Environment
# Based on Ubuntu with XFCE desktop and noVNC for browser access

FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV DISPLAY=:1
ENV VNC_PORT=5901
ENV NOVNC_PORT=6080
ENV RESOLUTION=1920x1080

# Install dependencies
RUN apt-get update && apt-get install -y \
    xfce4 \
    xfce4-goodies \
    tigervnc-standalone-server \
    tigervnc-common \
    novnc \
    websockify \
    net-tools \
    curl \
    wget \
    firefox \
    chromium-browser \
    git \
    python3 \
    python3-pip \
    supervisor \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create necessary directories
RUN mkdir -p /root/.vnc /root/.config/autostart

# Set VNC password (default: vncpassword)
RUN echo "vncpassword" | vncpasswd -f > /root/.vnc/passwd && \
    chmod 600 /root/.vnc/passwd

# Create VNC startup script
RUN echo '#!/bin/sh\n\
unset SESSION_MANAGER\n\
unset DBUS_SESSION_BUS_ADDRESS\n\
startxfce4 &' > /root/.vnc/xstartup && \
    chmod +x /root/.vnc/xstartup

# Create supervisord configuration
RUN mkdir -p /var/log/supervisor
COPY supervisord.conf /etc/supervisor/conf.d/supervisord.conf

# Expose VNC and noVNC ports
EXPOSE 5901 6080

# Start supervisor
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/supervisord.conf"]
