# Virtual Browser Environment

## Overview

This repository includes a virtualized browser environment that allows you to run a full desktop environment with web browsers in a containerized environment, accessible through your web browser via noVNC.

## Features

- 🖥️ **Full Desktop Environment**: XFCE desktop environment running in a container
- 🌐 **Browser Access**: Access via web browser (noVNC) - no VNC client needed
- 🔒 **Isolated Environment**: Run in a containerized, isolated environment
- 🚀 **One Command Setup**: Single command to start the entire environment
- 🔧 **Pre-installed Browsers**: Firefox and Chromium browsers included
- 📊 **High Resolution**: 1920x1080 default resolution

## Quick Start

### Prerequisites

- Docker (version 20.10 or higher)
- Docker Compose (version 2.0 or higher)
- At least 4GB of available RAM
- 10GB of available disk space

### Installation

1. **Clone the repository** (if not already done):
   ```bash
   git clone https://github.com/realharryhero/bug-bounty-toolkit.git
   cd bug-bounty-toolkit
   ```

2. **Start the virtual browser** with a single command:
   ```bash
   ./start-virtual-browser.sh
   ```

3. **Access the browser**:
   - Open your web browser
   - Navigate to: `http://localhost:6080`
   - Click "Connect" to access the desktop environment

### First Time Setup

The first time you run the script, it will:
1. Build the Docker image (this may take 5-10 minutes)
2. Start the container
3. Initialize the desktop environment

Subsequent runs will be much faster as the image is already built.

## Usage

### Starting the Environment

```bash
./start-virtual-browser.sh
```

### Accessing the Browser

Once started, access the virtual browser at:
- **Web Interface**: http://localhost:6080
- **VNC Client** (optional): localhost:5901 (password: `vncpassword`)

### Available Browsers

The environment comes with:
- **Firefox**: Click the Firefox icon in the desktop
- **Chromium**: Available in the applications menu

### Stopping the Environment

```bash
docker-compose down
```

### Restarting the Environment

```bash
docker-compose restart
```

### Viewing Logs

```bash
docker-compose logs -f
```

## Configuration

### Changing Resolution

Edit `docker-compose.yml` and modify the `RESOLUTION` environment variable:

```yaml
environment:
  - RESOLUTION=1920x1080  # Change to your preferred resolution
```

### Changing VNC Password

To change the default VNC password, edit the `Dockerfile` and replace `vncpassword` with your desired password:

```dockerfile
RUN echo "your-new-password" | vncpasswd -f > /root/.vnc/passwd
```

Then rebuild the image:
```bash
docker-compose build
```

### Custom Ports

To change the default ports, edit `docker-compose.yml`:

```yaml
ports:
  - "6080:6080"  # Change the first port number (host:container)
  - "5901:5901"
```

## Architecture

```
┌─────────────────────────────────────┐
│     Host Machine (Your Computer)     │
│                                      │
│  ┌────────────────────────────────┐ │
│  │    Web Browser (localhost:6080) │ │
│  └────────────┬───────────────────┘ │
│               │                      │
│               │ HTTP/WebSocket       │
│               │                      │
│  ┌────────────▼───────────────────┐ │
│  │     Docker Container           │ │
│  │                                │ │
│  │  ┌──────────────────────────┐ │ │
│  │  │  noVNC Web Server        │ │ │
│  │  │  (Port 6080)             │ │ │
│  │  └──────────┬───────────────┘ │ │
│  │             │                  │ │
│  │  ┌──────────▼───────────────┐ │ │
│  │  │  VNC Server              │ │ │
│  │  │  (Port 5901)             │ │ │
│  │  └──────────┬───────────────┘ │ │
│  │             │                  │ │
│  │  ┌──────────▼───────────────┐ │ │
│  │  │  XFCE Desktop            │ │ │
│  │  │  - Firefox               │ │ │
│  │  │  - Chromium              │ │ │
│  │  │  - Terminal              │ │ │
│  │  └──────────────────────────┘ │ │
│  └────────────────────────────────┘ │
└─────────────────────────────────────┘
```

## Troubleshooting

### Container won't start

1. Check if Docker is running:
   ```bash
   docker info
   ```

2. Check container logs:
   ```bash
   docker-compose logs
   ```

3. Ensure ports 6080 and 5901 are not in use:
   ```bash
   # On Linux/Mac
   lsof -i :6080
   lsof -i :5901
   
   # On Windows
   netstat -ano | findstr :6080
   netstat -ano | findstr :5901
   ```

### Can't connect to the browser interface

1. Verify the container is running:
   ```bash
   docker ps
   ```

2. Check if the port is properly exposed:
   ```bash
   curl http://localhost:6080
   ```

3. Try using your machine's IP address instead of localhost:
   ```bash
   http://<your-ip>:6080
   ```

### Desktop environment is slow

1. Increase allocated memory in `docker-compose.yml`:
   ```yaml
   shm_size: '4gb'  # Increase from 2gb
   ```

2. Close unnecessary applications within the virtual desktop

3. Lower the resolution in the RESOLUTION environment variable

### Browser crashes or is unresponsive

1. Restart the container:
   ```bash
   docker-compose restart
   ```

2. Check available system resources:
   ```bash
   docker stats
   ```

## Advanced Usage

### Installing Additional Software

You can install additional software by modifying the Dockerfile:

```dockerfile
RUN apt-get update && apt-get install -y \
    your-package-name \
    && apt-get clean
```

Then rebuild:
```bash
docker-compose build
```

### Persisting Data

Browser data is persisted in a Docker volume named `browser-data`. To back it up:

```bash
docker run --rm -v bug-bounty-toolkit_browser-data:/data -v $(pwd):/backup ubuntu tar czf /backup/browser-backup.tar.gz /data
```

To restore:
```bash
docker run --rm -v bug-bounty-toolkit_browser-data:/data -v $(pwd):/backup ubuntu tar xzf /backup/browser-backup.tar.gz -C /
```

### Running Multiple Instances

To run multiple instances, create a copy of `docker-compose.yml` with different:
- Container name
- Port mappings
- Volume names

## Security Considerations

⚠️ **Important Security Notes**:

1. **Default Password**: The default VNC password is `vncpassword`. Change it for production use.
2. **Network Exposure**: By default, the service binds to all interfaces (0.0.0.0). For local use only, bind to 127.0.0.1:
   ```yaml
   ports:
     - "127.0.0.1:6080:6080"
   ```
3. **Untrusted Content**: Only browse trusted websites within the virtual environment
4. **Updates**: Regularly rebuild the image to get security updates:
   ```bash
   docker-compose build --no-cache
   ```

## Performance Tips

1. **Allocate sufficient resources** to Docker:
   - Minimum 4GB RAM
   - 2+ CPU cores recommended

2. **Close unused applications** in the virtual desktop

3. **Use hardware acceleration** if available (Docker Desktop settings)

4. **Disable animations** in XFCE for better performance:
   - Settings → Window Manager Tweaks → Compositor → Disable composition

## Integration with Bug Bounty Toolkit

The virtual browser can be used in conjunction with the bug bounty toolkit for:
- Safe browsing of potentially malicious sites
- Isolated testing environment
- Capturing screenshots and recordings
- Testing client-side vulnerabilities in a controlled environment

## Support

For issues or questions:
- Create an issue on GitHub
- Check Docker and Docker Compose documentation
- Review the logs with `docker-compose logs`

## License

This virtual browser environment is part of the Bug Bounty Toolkit and is licensed under the MIT License.
