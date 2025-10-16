# Virtual Browser Environment Configuration Examples

## Custom Resolution

### 4K Resolution
Edit `docker-compose.yml`:
```yaml
environment:
  - RESOLUTION=3840x2160
```

### 720p (Lower resource usage)
```yaml
environment:
  - RESOLUTION=1280x720
```

## Custom Ports

### Change noVNC Port
Edit `docker-compose.yml`:
```yaml
ports:
  - "127.0.0.1:8080:6080"  # Change 8080 to desired port
  - "127.0.0.1:5901:5901"
```

### Enable External Access
By default, the virtual browser binds to localhost only for security.
To enable access from other machines on your network, edit `docker-compose.yml`:
```yaml
ports:
  - "6080:6080"  # Remove 127.0.0.1: prefix to bind to all interfaces
  - "5901:5901"
```

**⚠️ Security Warning**: Only enable external access on trusted networks. Consider using a reverse proxy with authentication for production use.

## Multiple Instances

To run multiple instances, create `docker-compose-instance2.yml`:

```yaml
version: '3.8'

services:
  virtual-browser-2:
    build: .
    container_name: virtual-browser-2
    ports:
      - "6081:6080"  # Different port
      - "5902:5901"
    environment:
      - DISPLAY=:1
      - RESOLUTION=1920x1080
    volumes:
      - browser-data-2:/root  # Different volume
    restart: unless-stopped
    shm_size: '2gb'
    stdin_open: true
    tty: true

volumes:
  browser-data-2:
    driver: local
```

Start with:
```bash
docker-compose -f docker-compose-instance2.yml up -d
```

## Custom Software Installation

### Add Python Development Tools
Edit `Dockerfile`:
```dockerfile
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    python3-dev \
    && apt-get clean
```

### Add Node.js and npm
```dockerfile
RUN curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get install -y nodejs && \
    apt-get clean
```

### Add Visual Studio Code
```dockerfile
RUN wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > packages.microsoft.gpg && \
    install -o root -g root -m 644 packages.microsoft.gpg /etc/apt/trusted.gpg.d/ && \
    sh -c 'echo "deb [arch=amd64] https://packages.microsoft.com/repos/vscode stable main" > /etc/apt/sources.list.d/vscode.list' && \
    apt-get update && \
    apt-get install -y code && \
    apt-get clean
```

### Add Security Testing Tools
```dockerfile
RUN apt-get update && apt-get install -y \
    nmap \
    wireshark \
    tcpdump \
    burpsuite \
    && apt-get clean
```

## Resource Allocation

### High Performance Setup
Edit `docker-compose.yml`:
```yaml
services:
  virtual-browser:
    # ... other config ...
    shm_size: '4gb'  # Increase shared memory
    deploy:
      resources:
        limits:
          cpus: '4'
          memory: 8G
        reservations:
          cpus: '2'
          memory: 4G
```

### Low Resource Setup
```yaml
services:
  virtual-browser:
    # ... other config ...
    shm_size: '1gb'
    deploy:
      resources:
        limits:
          cpus: '1'
          memory: 2G
```

## VNC Password Change

### Using Environment Variable
Edit `docker-compose.yml`:
```yaml
environment:
  - VNC_PASSWORD=mysecurepassword
```

Update `Dockerfile`:
```dockerfile
# Replace the static password line with:
RUN echo "${VNC_PASSWORD:-vncpassword}" | vncpasswd -f > /root/.vnc/passwd
```

### Using Docker Secret
Create password file:
```bash
echo "mysecurepassword" > vnc_password.txt
```

Edit `docker-compose.yml`:
```yaml
services:
  virtual-browser:
    secrets:
      - vnc_password
    # ... rest of config ...

secrets:
  vnc_password:
    file: ./vnc_password.txt
```

## Persistent Browser Profile

### Save Firefox Profile
The browser profile is automatically saved in the `browser-data` volume.

### Backup Profile
```bash
docker run --rm -v bug-bounty-toolkit_browser-data:/data \
    -v $(pwd):/backup ubuntu \
    tar czf /backup/firefox-profile-$(date +%Y%m%d).tar.gz /data/.mozilla
```

### Restore Profile
```bash
docker run --rm -v bug-bounty-toolkit_browser-data:/data \
    -v $(pwd):/backup ubuntu \
    tar xzf /backup/firefox-profile-YYYYMMDD.tar.gz -C /
```

## Network Configuration

### Connect to Host Network
Edit `docker-compose.yml`:
```yaml
services:
  virtual-browser:
    network_mode: "host"
    # Remove ports section when using host network
```

### Custom Network
```yaml
services:
  virtual-browser:
    networks:
      - browser-network

networks:
  browser-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/16
```

## Automated Startup

### Linux/Mac - Systemd Service
Create `/etc/systemd/system/virtual-browser.service`:
```ini
[Unit]
Description=Virtual Browser Environment
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/path/to/bug-bounty-toolkit
ExecStart=/usr/local/bin/docker-compose up -d
ExecStop=/usr/local/bin/docker-compose down

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable virtual-browser
sudo systemctl start virtual-browser
```

### Windows - Task Scheduler
1. Open Task Scheduler
2. Create Basic Task
3. Trigger: At system startup
4. Action: Start a program
5. Program: `C:\path\to\start-virtual-browser.bat`

## SSL/TLS Configuration

### Enable HTTPS for noVNC
Create SSL certificates:
```bash
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout self.pem -out self.pem
```

Update `supervisord.conf`:
```ini
[program:novnc]
command=/usr/share/novnc/utils/novnc_proxy --vnc localhost:5901 --listen 6080 --cert /etc/ssl/certs/self.pem
```

## Integration with Reverse Proxy

### Nginx Configuration
```nginx
server {
    listen 80;
    server_name browser.example.com;

    location / {
        proxy_pass http://localhost:6080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```

### Traefik Labels
Add to `docker-compose.yml`:
```yaml
services:
  virtual-browser:
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.browser.rule=Host(`browser.example.com`)"
      - "traefik.http.services.browser.loadbalancer.server.port=6080"
```

## Debugging

### Enable Verbose Logging
Edit `supervisord.conf`:
```ini
[supervisord]
logfile=/var/log/supervisor/supervisord.log
loglevel=debug
```

### Access VNC Directly
Use a VNC client (like RealVNC or TigerVNC):
```
Host: localhost
Port: 5901
Password: vncpassword
```

## Performance Optimization

### Disable Unnecessary Services
Edit `Dockerfile` to remove services you don't need:
```dockerfile
# Comment out packages you don't need
# chromium-browser \
```

### Use Lighter Desktop Environment
Replace XFCE with LXDE (edit `Dockerfile`):
```dockerfile
RUN apt-get update && apt-get install -y \
    lxde \
    # ... rest of packages
```

### Enable GPU Acceleration (Docker Desktop)
Edit `docker-compose.yml`:
```yaml
services:
  virtual-browser:
    runtime: nvidia
    environment:
      - NVIDIA_VISIBLE_DEVICES=all
```
