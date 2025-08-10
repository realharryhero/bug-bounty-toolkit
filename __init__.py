"""
Bug Bounty Automation Toolkit
A comprehensive, professional-grade bug bounty automation toolkit for ethical security research.
"""

__version__ = "1.0.0"
__author__ = "Bug Bounty Toolkit Contributors"
__license__ = "MIT"

# Legal disclaimer
LEGAL_DISCLAIMER = """
LEGAL DISCLAIMER AND TERMS OF USE

This Bug Bounty Automation Toolkit is designed exclusively for authorized security research and testing.
By using this software, you acknowledge and agree to the following terms:

1. AUTHORIZED USE ONLY: You may only use this toolkit against systems you own, have explicit written
   permission to test, or are within the scope of authorized bug bounty programs.

2. NO UNAUTHORIZED TESTING: Testing systems without proper authorization is illegal and may result
   in criminal and civil liability.

3. COMPLIANCE: You are responsible for ensuring all activities comply with applicable laws,
   regulations, and terms of service.

4. NO WARRANTY: This software is provided "as-is" without any warranties or guarantees.

5. LIMITATION OF LIABILITY: The authors and contributors are not responsible for any misuse,
   damage, or legal consequences resulting from the use of this toolkit.

BY USING THIS SOFTWARE, YOU ACCEPT FULL RESPONSIBILITY FOR YOUR ACTIONS AND AGREE TO USE IT
ONLY FOR AUTHORIZED, LEGAL, AND ETHICAL PURPOSES.
"""

def show_disclaimer():
    """Display the legal disclaimer."""
    print("=" * 80)
    print("BUG BOUNTY AUTOMATION TOOLKIT")
    print("=" * 80)
    print(LEGAL_DISCLAIMER)
    print("=" * 80)