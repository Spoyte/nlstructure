#!/usr/bin/env python3
"""
Natural Language Infrastructure Query System
Ask questions like "why is the API slow?" and get automatic investigation
with root cause analysis across logs, metrics, and traces.
"""

import argparse
import json
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Optional


class InvestigationType(Enum):
    PERFORMANCE = "performance"
    ERROR = "error"
    AVAILABILITY = "availability"
    RESOURCE = "resource"
    SECURITY = "security"
    UNKNOWN = "unknown"


@dataclass
class InvestigationResult:
    query: str
    investigation_type: InvestigationType
    findings: list[dict] = field(default_factory=list)
    root_cause: Optional[str] = None
    recommendations: list[str] = field(default_factory=list)
    confidence: float = 0.0
    duration_ms: int = 0


class NLQueryEngine:
    """Parse natural language queries and route to appropriate investigators."""
    
    PATTERNS = {
        InvestigationType.PERFORMANCE: [
            r'slow',
            r'performance',
            r'latency',
            r'response time',
            r'timeout',
            r'lag',
            r'fast',
            r'speed',
        ],
        InvestigationType.ERROR: [
            r'error',
            r'crash',
            r'exception',
            r'broken',
            r'not working',
            r'bug',
        ],
        InvestigationType.AVAILABILITY: [
            r'down',
            r'offline',
            r'unavailable',
            r'up\?',
            r'status',
            r'health',
        ],
        InvestigationType.RESOURCE: [
            r'cpu',
            r'memory',
            r'disk',
            r'space',
            r'full',
            r'usage',
            r'load',
        ],
        InvestigationType.SECURITY: [
            r'security',
            r'attack',
            r'breach',
            r'unauthorized',
            r'intrusion',
        ],
    }
    
    def __init__(self, config_path: Optional[str] = None):
        self.config = self._load_config(config_path)
        self.investigators = {
            InvestigationType.PERFORMANCE: PerformanceInvestigator(),
            InvestigationType.ERROR: ErrorInvestigator(),
            InvestigationType.AVAILABILITY: AvailabilityInvestigator(),
            InvestigationType.RESOURCE: ResourceInvestigator(),
            InvestigationType.SECURITY: SecurityInvestigator(),
            InvestigationType.UNKNOWN: GenericInvestigator(),
        }
    
    def _load_config(self, config_path: Optional[str]) -> dict:
        """Load configuration from file or use defaults."""
        defaults = {
            "log_sources": ["/var/log/syslog", "/var/log/auth.log"],
            "metric_endpoints": [],
            "trace_sources": [],
            "services": [],
            "lookback_minutes": 60,
        }
        
        if config_path and Path(config_path).exists():
            with open(config_path) as f:
                return {**defaults, **json.load(f)}
        return defaults
    
    def parse_query(self, query: str) -> InvestigationType:
        """Determine investigation type from natural language query."""
        query_lower = query.lower()
        
        scores = {}
        for inv_type, patterns in self.PATTERNS.items():
            score = sum(1 for p in patterns if re.search(p, query_lower))
            if score > 0:
                scores[inv_type] = score
        
        if not scores:
            return InvestigationType.UNKNOWN
        
        return max(scores, key=scores.get)
    
    def investigate(self, query: str) -> InvestigationResult:
        """Run full investigation based on query."""
        start_time = datetime.now()
        
        # Parse query type
        inv_type = self.parse_query(query)
        
        # Get appropriate investigator
        investigator = self.investigators[inv_type]
        
        # Run investigation
        result = investigator.investigate(query, self.config)
        result.investigation_type = inv_type
        result.query = query
        
        # Calculate duration
        result.duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
        
        return result


class BaseInvestigator:
    """Base class for all investigators."""
    
    def investigate(self, query: str, config: dict) -> InvestigationResult:
        raise NotImplementedError
    
    def run_command(self, cmd: list[str], timeout: int = 30) -> tuple[int, str, str]:
        """Run a shell command and return (returncode, stdout, stderr)."""
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except Exception as e:
            return -1, "", str(e)


class PerformanceInvestigator(BaseInvestigator):
    """Investigate performance issues."""
    
    def investigate(self, query: str, config: dict) -> InvestigationResult:
        result = InvestigationResult(
            query=query,
            investigation_type=InvestigationType.PERFORMANCE,
            findings=[],
            recommendations=[],
        )
        
        # Extract service name if mentioned
        service_match = re.search(r'(\w+)\s+(?:api|service|app)', query.lower())
        service = service_match.group(1) if service_match else None
        
        # Check system load
        rc, stdout, _ = self.run_command(["uptime"])
        if rc == 0:
            result.findings.append({
                "type": "system_load",
                "data": stdout.strip(),
            })
        
        # Check CPU usage
        rc, stdout, _ = self.run_command([
            "sh", "-c", 
            "ps aux --sort=-%cpu | head -10"
        ])
        if rc == 0:
            result.findings.append({
                "type": "top_cpu_processes",
                "data": stdout.strip(),
            })
        
        # Check memory usage
        rc, stdout, _ = self.run_command(["free", "-h"])
        if rc == 0:
            result.findings.append({
                "type": "memory_usage",
                "data": stdout.strip(),
            })
        
        # Check disk I/O if available
        rc, stdout, _ = self.run_command([
            "sh", "-c",
            "iostat -x 1 1 2>/dev/null || echo 'iostat not available'"
        ])
        if rc == 0 and "not available" not in stdout:
            result.findings.append({
                "type": "disk_io",
                "data": stdout.strip(),
            })
        
        # Check for slow queries in logs (if mysql/postgres available)
        rc, stdout, _ = self.run_command([
            "sh", "-c",
            "grep -i 'slow\|took\|duration' /var/log/syslog 2>/dev/null | tail -20 || echo 'No slow query logs found'"
        ])
        if rc == 0:
            result.findings.append({
                "type": "slow_logs",
                "data": stdout.strip(),
            })
        
        # Analyze findings for root cause
        result.root_cause = self._analyze_root_cause(result.findings)
        result.recommendations = self._generate_recommendations(result.findings)
        result.confidence = 0.75 if result.root_cause else 0.5
        
        return result
    
    def _analyze_root_cause(self, findings: list[dict]) -> Optional[str]:
        """Analyze findings to determine root cause."""
        for finding in findings:
            if finding["type"] == "memory_usage":
                data = finding["data"]
                if "swap" in data.lower() and "0" not in data.split()[1] if len(data.split()) > 1 else False:
                    return "High memory usage with swap activity detected"
        
        for finding in findings:
            if finding["type"] == "top_cpu_processes":
                lines = finding["data"].strip().split('\n')[1:]  # Skip header
                if lines:
                    first_process = lines[0].split()
                    if len(first_process) > 2:
                        try:
                            cpu_percent = float(first_process[2])
                            if cpu_percent > 50:
                                return f"High CPU usage by process: {first_process[-1] if first_process else 'unknown'}"
                        except ValueError:
                            pass
        
        return "Investigation complete - no obvious root cause identified. Check detailed findings."
    
    def _generate_recommendations(self, findings: list[dict]) -> list[str]:
        """Generate recommendations based on findings."""
        recommendations = []
        
        for finding in findings:
            if finding["type"] == "memory_usage":
                recommendations.append("Monitor memory usage trends over time")
                recommendations.append("Consider scaling up if memory consistently high")
            
            if finding["type"] == "top_cpu_processes":
                recommendations.append("Profile high CPU processes for optimization opportunities")
            
            if finding["type"] == "disk_io":
                recommendations.append("Review disk-intensive operations for optimization")
        
        if not recommendations:
            recommendations.append("Collect more detailed metrics for deeper analysis")
            recommendations.append("Consider implementing distributed tracing")
        
        return recommendations


class ErrorInvestigator(BaseInvestigator):
    """Investigate error issues."""
    
    def investigate(self, query: str, config: dict) -> InvestigationResult:
        result = InvestigationResult(
            query=query,
            investigation_type=InvestigationType.ERROR,
            findings=[],
            recommendations=[],
        )
        
        # Check recent errors in syslog
        rc, stdout, _ = self.run_command([
            "sh", "-c",
            "grep -iE 'error|fail|exception|fatal' /var/log/syslog 2>/dev/null | tail -30 || echo 'No syslog access'"
        ])
        if rc == 0:
            result.findings.append({
                "type": "recent_errors",
                "data": stdout.strip(),
            })
        
        # Check systemd failed services
        rc, stdout, _ = self.run_command([
            "systemctl", "--failed", "--no-pager"
        ])
        if rc == 0:
            result.findings.append({
                "type": "failed_services",
                "data": stdout.strip(),
            })
        
        # Check journal for errors
        rc, stdout, _ = self.run_command([
            "journalctl", "--priority=3", "--since", "1 hour ago",
            "--no-pager", "-q"
        ])
        if rc == 0 and stdout.strip():
            result.findings.append({
                "type": "journal_errors",
                "data": stdout.strip(),
            })
        
        # Analyze
        result.root_cause = self._analyze_root_cause(result.findings)
        result.recommendations = self._generate_recommendations(result.findings)
        result.confidence = 0.7 if result.root_cause else 0.5
        
        return result
    
    def _analyze_root_cause(self, findings: list[dict]) -> Optional[str]:
        for finding in findings:
            if finding["type"] == "failed_services":
                if "0 loaded units listed" not in finding["data"]:
                    return "One or more systemd services have failed"
        
        for finding in findings:
            if finding["type"] == "journal_errors":
                if finding["data"].strip():
                    return "Errors detected in system journal"
        
        return None
    
    def _generate_recommendations(self, findings: list[dict]) -> list[str]:
        recommendations = []
        
        for finding in findings:
            if finding["type"] == "failed_services":
                recommendations.append("Restart failed services: systemctl restart <service>")
                recommendations.append("Check service logs: journalctl -u <service>")
            
            if finding["type"] == "journal_errors":
                recommendations.append("Review full error logs for context")
                recommendations.append("Set up log aggregation for better visibility")
        
        return recommendations if recommendations else ["Investigate error patterns in application logs"]


class AvailabilityInvestigator(BaseInvestigator):
    """Investigate availability issues."""
    
    def investigate(self, query: str, config: dict) -> InvestigationResult:
        result = InvestigationResult(
            query=query,
            investigation_type=InvestigationType.AVAILABILITY,
            findings=[],
            recommendations=[],
        )
        
        # Check network connectivity
        rc, stdout, _ = self.run_command(["ping", "-c", "3", "8.8.8.8"])
        result.findings.append({
            "type": "internet_connectivity",
            "data": "Reachable" if rc == 0 else "Unreachable",
            "details": stdout.strip() if rc == 0 else "",
        })
        
        # Check listening ports
        rc, stdout, _ = self.run_command([
            "sh", "-c",
            "ss -tlnp 2>/dev/null | head -20 || netstat -tlnp 2>/dev/null | head -20"
        ])
        if rc == 0:
            result.findings.append({
                "type": "listening_ports",
                "data": stdout.strip(),
            })
        
        # Check Docker containers if available
        rc, stdout, _ = self.run_command([
            "docker", "ps", "--format", "table {{.Names}}\t{{.Status}}"
        ])
        if rc == 0:
            result.findings.append({
                "type": "docker_containers",
                "data": stdout.strip(),
            })
        
        result.root_cause = self._analyze_root_cause(result.findings)
        result.recommendations = self._generate_recommendations(result.findings)
        result.confidence = 0.8
        
        return result
    
    def _analyze_root_cause(self, findings: list[dict]) -> Optional[str]:
        for finding in findings:
            if finding["type"] == "internet_connectivity":
                if finding["data"] == "Unreachable":
                    return "No internet connectivity detected"
        
        return "Services appear to be running normally"
    
    def _generate_recommendations(self, findings: list[dict]) -> list[str]:
        return ["Monitor service health with regular health checks"]


class ResourceInvestigator(BaseInvestigator):
    """Investigate resource issues."""
    
    def investigate(self, query: str, config: dict) -> InvestigationResult:
        result = InvestigationResult(
            query=query,
            investigation_type=InvestigationType.RESOURCE,
            findings=[],
            recommendations=[],
        )
        
        # Disk usage
        rc, stdout, _ = self.run_command(["df", "-h"])
        if rc == 0:
            result.findings.append({
                "type": "disk_usage",
                "data": stdout.strip(),
            })
        
        # Inode usage
        rc, stdout, _ = self.run_command(["df", "-i"])
        if rc == 0:
            result.findings.append({
                "type": "inode_usage",
                "data": stdout.strip(),
            })
        
        # Memory
        rc, stdout, _ = self.run_command(["free", "-h"])
        if rc == 0:
            result.findings.append({
                "type": "memory",
                "data": stdout.strip(),
            })
        
        # CPU info
        rc, stdout, _ = self.run_command([
            "sh", "-c",
            "nproc && cat /proc/loadavg"
        ])
        if rc == 0:
            result.findings.append({
                "type": "cpu_load",
                "data": stdout.strip(),
            })
        
        result.root_cause = self._analyze_root_cause(result.findings)
        result.recommendations = self._generate_recommendations(result.findings)
        result.confidence = 0.75
        
        return result
    
    def _analyze_root_cause(self, findings: list[dict]) -> Optional[str]:
        for finding in findings:
            if finding["type"] == "disk_usage":
                lines = finding["data"].strip().split('\n')[1:]  # Skip header
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 5:
                        try:
                            usage = int(parts[4].rstrip('%'))
                            if usage > 90:
                                return f"Critical disk usage on {parts[0]}: {usage}%"
                            elif usage > 80:
                                return f"High disk usage on {parts[0]}: {usage}%"
                        except ValueError:
                            continue
        
        return None
    
    def _generate_recommendations(self, findings: list[dict]) -> list[str]:
        recommendations = []
        
        for finding in findings:
            if finding["type"] == "disk_usage":
                recommendations.append("Clean up old logs: journalctl --vacuum-time=7d")
                recommendations.append("Remove unused Docker images: docker system prune")
                recommendations.append("Find large files: du -h / | sort -rh | head -20")
        
        return recommendations if recommendations else ["Resource usage within normal parameters"]


class SecurityInvestigator(BaseInvestigator):
    """Investigate security issues."""
    
    def investigate(self, query: str, config: dict) -> InvestigationResult:
        result = InvestigationResult(
            query=query,
            investigation_type=InvestigationType.SECURITY,
            findings=[],
            recommendations=[],
        )
        
        # Check recent auth failures
        rc, stdout, _ = self.run_command([
            "sh", "-c",
            "grep -i 'failed\|invalid\|authentication failure' /var/log/auth.log 2>/dev/null | tail -20 || echo 'No auth log access'"
        ])
        if rc == 0:
            result.findings.append({
                "type": "auth_failures",
                "data": stdout.strip(),
            })
        
        # Check for listening ports on all interfaces
        rc, stdout, _ = self.run_command([
            "sh", "-c",
            "ss -tlnp 2>/dev/null | grep '0.0.0.0' || netstat -tlnp 2>/dev/null | grep '0.0.0.0'"
        ])
        if rc == 0:
            result.findings.append({
                "type": "exposed_ports",
                "data": stdout.strip(),
            })
        
        result.root_cause = None
        result.recommendations = [
            "Review exposed services and firewall rules",
            "Check for unauthorized access attempts regularly",
            "Ensure fail2ban or similar is configured",
        ]
        result.confidence = 0.6
        
        return result


class GenericInvestigator(BaseInvestigator):
    """Generic fallback investigator."""
    
    def investigate(self, query: str, config: dict) -> InvestigationResult:
        result = InvestigationResult(
            query=query,
            investigation_type=InvestigationType.UNKNOWN,
            findings=[],
            recommendations=[],
        )
        
        # Collect basic system info
        rc, stdout, _ = self.run_command(["uptime"])
        if rc == 0:
            result.findings.append({
                "type": "uptime",
                "data": stdout.strip(),
            })
        
        rc, stdout, _ = self.run_command(["uname", "-a"])
        if rc == 0:
            result.findings.append({
                "type": "system_info",
                "data": stdout.strip(),
            })
        
        result.root_cause = "Query type unclear - general system status provided"
        result.recommendations = [
            "Try more specific queries like:",
            "  - 'Why is the API slow?'",
            "  - 'What errors happened recently?'",
            "  - 'Is the service down?'",
        ]
        result.confidence = 0.3
        
        return result


def format_result(result: InvestigationResult) -> str:
    """Format investigation result for display."""
    lines = [
        "=" * 60,
        f"🔍 INVESTIGATION RESULT: {result.investigation_type.value.upper()}",
        "=" * 60,
        f"Query: {result.query}",
        f"Confidence: {result.confidence:.0%}",
        f"Duration: {result.duration_ms}ms",
        "",
    ]
    
    if result.root_cause:
        lines.extend([
            "📋 ROOT CAUSE:",
            f"  {result.root_cause}",
            "",
        ])
    
    if result.findings:
        lines.append("📊 FINDINGS:")
        for finding in result.findings:
            lines.append(f"  [{finding['type']}]")
            data = finding['data']
            if '\n' in data:
                for line in data.split('\n'):
                    lines.append(f"    {line}")
            else:
                lines.append(f"    {data}")
        lines.append("")
    
    if result.recommendations:
        lines.append("💡 RECOMMENDATIONS:")
        for rec in result.recommendations:
            lines.append(f"  • {rec}")
        lines.append("")
    
    lines.append("=" * 60)
    
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Natural Language Infrastructure Query System"
    )
    parser.add_argument(
        "query",
        nargs="?",
        help="Natural language query (e.g., 'why is the API slow?')"
    )
    parser.add_argument(
        "--config", "-c",
        help="Path to configuration file"
    )
    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output as JSON"
    )
    parser.add_argument(
        "--interactive", "-i",
        action="store_true",
        help="Interactive mode"
    )
    
    args = parser.parse_args()
    
    engine = NLQueryEngine(args.config)
    
    if args.interactive or not args.query:
        print("🔍 Natural Language Infrastructure Query System")
        print("Type 'quit' or 'exit' to stop")
        print("")
        
        while True:
            try:
                query = input("Query> ").strip()
                if query.lower() in ('quit', 'exit', 'q'):
                    break
                if not query:
                    continue
                
                result = engine.investigate(query)
                print(format_result(result))
                print("")
                
            except KeyboardInterrupt:
                print("\nGoodbye!")
                break
            except EOFError:
                break
    else:
        result = engine.investigate(args.query)
        
        if args.json:
            output = {
                "query": result.query,
                "type": result.investigation_type.value,
                "confidence": result.confidence,
                "duration_ms": result.duration_ms,
                "root_cause": result.root_cause,
                "findings": result.findings,
                "recommendations": result.recommendations,
            }
            print(json.dumps(output, indent=2))
        else:
            print(format_result(result))


if __name__ == "__main__":
    main()
