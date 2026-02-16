# Natural Language Infrastructure Query System

Ask questions like "why is the API slow?" and get automatic investigation with root cause analysis across logs, metrics, and traces.

## Features

- **Natural Language Parsing**: Understands queries about performance, errors, availability, resources, and security
- **Multi-Source Investigation**: Checks system logs, metrics, service status, and resource usage
- **Root Cause Analysis**: Automatically identifies likely causes from collected data
- **Actionable Recommendations**: Provides specific next steps based on findings

## Installation

```bash
cd projects/nl-infrastructure-queries
chmod +x nl_query.py
```

## Usage

### Interactive Mode
```bash
./nl_query.py -i
```

### Single Query
```bash
./nl_query.py "why is the API slow?"
./nl_query.py "what errors happened recently?"
./nl_query.py "is the database down?"
./nl_query.py "check disk space"
```

### JSON Output
```bash
./nl_query.py "why is the API slow?" --json
```

## Query Types

| Type | Example Queries |
|------|-----------------|
| Performance | "why is the API slow?", "high latency", "response timeout" |
| Error | "what failed?", "any errors?", "why is it crashing?" |
| Availability | "is the service down?", "check status", "health check" |
| Resource | "disk full?", "high memory usage", "CPU load" |
| Security | "security issues?", "failed logins", "unauthorized access" |

## Example Output

```
============================================================
🔍 INVESTIGATION RESULT: PERFORMANCE
============================================================
Query: why is the API slow?
Confidence: 75%
Duration: 245ms

📋 ROOT CAUSE:
  High CPU usage by process: python3

📊 FINDINGS:
  [system_load]
    16:34:00 up 5 days, load average: 2.45, 1.89, 1.23
  [top_cpu_processes]
    USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
    root     12345 85.2  4.5 123456 78901 ?        R    16:30   2:34 python3 app.py
  ...

💡 RECOMMENDATIONS:
  • Profile high CPU processes for optimization opportunities
  • Monitor memory usage trends over time
  • Consider scaling up if memory consistently high

============================================================
```

## Configuration

Create a config file to customize data sources:

```json
{
  "log_sources": ["/var/log/syslog", "/var/log/myapp/app.log"],
  "metric_endpoints": ["http://prometheus:9090"],
  "trace_sources": ["http://jaeger:16686"],
  "services": ["api", "worker", "database"],
  "lookback_minutes": 60
}
```

Use with: `./nl_query.py -c config.json "query"`

## Architecture

```
┌─────────────────┐
│  User Query     │
└────────┬────────┘
         ▼
┌─────────────────┐
│  Query Parser   │──→ Investigation Type
└────────┬────────┘
         ▼
┌─────────────────┐
│ Investigator    │──→ Performance/Error/Resource/etc
└────────┬────────┘
         ▼
┌─────────────────┐
│ Data Collection │──→ Logs, Metrics, System Status
└────────┬────────┘
         ▼
┌─────────────────┐
│ Root Cause      │──→ Analysis & Recommendations
│ Analysis        │
└─────────────────┘
```

## Extending

Add new investigators by subclassing `BaseInvestigator`:

```python
class CustomInvestigator(BaseInvestigator):
    def investigate(self, query: str, config: dict) -> InvestigationResult:
        # Your investigation logic
        pass
```

## License

MIT
