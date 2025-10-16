# Quick Start Guide - Virtual Browser

## What is this?

A virtualized desktop environment with web browsers that you can access through your web browser. No complex setup needed!

## Installation (One-Time Setup)

### Step 1: Install Prerequisites

**On Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install docker.io docker-compose
sudo usermod -aG docker $USER
# Log out and back in for group changes to take effect
```

**On macOS:**
```bash
brew install docker docker-compose
# Or download Docker Desktop from https://www.docker.com/products/docker-desktop
```

**On Windows:**
- Download and install [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop)
- Enable WSL 2 if prompted

### Step 2: Clone the Repository

```bash
git clone https://github.com/realharryhero/bug-bounty-toolkit.git
cd bug-bounty-toolkit
```

## Usage

### Starting the Virtual Browser

**Single Command:**
```bash
./start-virtual-browser.sh
```

**On Windows (PowerShell):**
```powershell
docker-compose up -d
```

### Accessing the Browser

1. Wait 10-15 seconds for the environment to start
2. Open your web browser
3. Navigate to: **http://localhost:6080**
4. Click "Connect"
5. You'll see a desktop environment with Firefox and Chromium browsers

### Using the Virtual Browser

- **Launch Firefox**: Click the Firefox icon on the desktop
- **Launch Chromium**: Click Applications → Internet → Chromium
- **Open Terminal**: Right-click desktop → Open Terminal Here
- **Install Software**: Use `apt-get install <package>` in terminal

### Stopping the Virtual Browser

```bash
docker-compose down
```

### Restarting

```bash
docker-compose restart
```

## Common Issues

### Port Already in Use

If port 6080 is already in use, edit `docker-compose.yml`:

```yaml
ports:
  - "8080:6080"  # Change 8080 to any available port
```

Then access via `http://localhost:8080`

### Container Won't Start

1. Check Docker is running:
   ```bash
   docker ps
   ```

2. View logs:
   ```bash
   docker-compose logs
   ```

3. Rebuild from scratch:
   ```bash
   docker-compose down -v
   docker-compose build --no-cache
   docker-compose up -d
   ```

### Slow Performance

1. Allocate more resources to Docker (Docker Desktop Settings)
   - RAM: At least 4GB
   - CPUs: At least 2 cores

2. Close unused applications in the virtual desktop

## What Can I Do With This?

- **Browse websites safely** in an isolated environment
- **Test web applications** without affecting your main system
- **Capture screenshots** of suspicious websites
- **Run security tools** in a controlled environment
- **Practice web scraping** without installing tools locally
- **Test browser extensions** safely

## Next Steps

For more advanced configuration and features, see the full documentation:
- [Virtual Browser Documentation](VIRTUAL_BROWSER.md)
- [Bug Bounty Toolkit Documentation](README.md)

## Need Help?

- Create an issue on [GitHub](https://github.com/realharryhero/bug-bounty-toolkit/issues)
- Check the [Troubleshooting Section](VIRTUAL_BROWSER.md#troubleshooting)
- Review Docker logs: `docker-compose logs -f`
