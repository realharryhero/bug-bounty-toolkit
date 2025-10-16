#!/bin/bash

# Demo script showing how to use the virtual browser with the bug bounty toolkit

echo "=============================================="
echo "  Bug Bounty Toolkit - Virtual Browser Demo"
echo "=============================================="
echo ""

# Check if virtual browser is running
if ! docker ps | grep -q "virtual-browser"; then
    echo "📦 Virtual browser is not running."
    echo "Starting virtual browser..."
    ./start-virtual-browser.sh
    
    echo ""
    echo "⏳ Waiting 15 seconds for services to fully initialize..."
    sleep 15
else
    echo "✅ Virtual browser is already running."
fi

echo ""
echo "=============================================="
echo "  Demo Use Cases"
echo "=============================================="
echo ""
echo "1. Safe Browsing for Recon:"
echo "   - Open http://localhost:6080 in your browser"
echo "   - Use Firefox/Chromium to safely browse target sites"
echo "   - Take screenshots of interesting findings"
echo ""
echo "2. Testing Client-Side Vulnerabilities:"
echo "   - Run XSS payloads in the isolated browser"
echo "   - Test JavaScript injection safely"
echo "   - Verify DOM manipulation attacks"
echo ""
echo "3. Using with Bug Bounty Toolkit:"
echo "   a. First, run reconnaissance:"
echo "      python main.py --recon subdomain --domain example.com"
echo ""
echo "   b. Then, manually verify findings in the virtual browser"
echo "      http://localhost:6080"
echo ""
echo "   c. Run targeted scans on verified endpoints:"
echo "      python main.py --scan xss --target https://target.example.com"
echo ""
echo "4. Installing Additional Tools:"
echo "   - Access the virtual browser terminal"
echo "   - Install tools: sudo apt-get install <tool>"
echo "   - Or use pip: pip3 install <package>"
echo ""
echo "=============================================="
echo ""
echo "🌐 Virtual Browser URL: http://localhost:6080"
echo "📚 Full Documentation: See VIRTUAL_BROWSER.md"
echo ""
echo "Press Ctrl+C to exit this demo message"
echo ""

# Keep script running so user can read the message
sleep infinity
