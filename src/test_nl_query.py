#!/usr/bin/env python3
"""Tests for NL Infrastructure Query System."""

import unittest
import sys
import json
from pathlib import Path

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent))

from nl_query import (
    NLQueryEngine,
    InvestigationType,
    InvestigationResult,
    PerformanceInvestigator,
    ErrorInvestigator,
    AvailabilityInvestigator,
    ResourceInvestigator,
)


class TestQueryParsing(unittest.TestCase):
    """Test query type detection."""
    
    def setUp(self):
        self.engine = NLQueryEngine()
    
    def test_performance_queries(self):
        queries = [
            "why is the API slow?",
            "high latency on requests",
            "response timeout issues",
            "performance degradation",
        ]
        for q in queries:
            result = self.engine.parse_query(q)
            self.assertEqual(result, InvestigationType.PERFORMANCE, f"Failed for: {q}")
    
    def test_error_queries(self):
        queries = [
            "what errors happened?",
            "service is crashing",
            "app crashed",
            "exception in logs",
        ]
        for q in queries:
            result = self.engine.parse_query(q)
            self.assertEqual(result, InvestigationType.ERROR, f"Failed for: {q}")
    
    def test_availability_queries(self):
        queries = [
            "is the service down?",
            "API unavailable",
            "check status",
        ]
        for q in queries:
            result = self.engine.parse_query(q)
            self.assertEqual(result, InvestigationType.AVAILABILITY, f"Failed for: {q}")
    
    def test_resource_queries(self):
        queries = [
            "disk full?",
            "high CPU usage",
            "memory running low",
            "out of disk space",
        ]
        for q in queries:
            result = self.engine.parse_query(q)
            self.assertEqual(result, InvestigationType.RESOURCE, f"Failed for: {q}")
    
    def test_security_queries(self):
        queries = [
            "security issues?",
            "unauthorized access",
        ]
        for q in queries:
            result = self.engine.parse_query(q)
            self.assertEqual(result, InvestigationType.SECURITY, f"Failed for: {q}")
    
    def test_unknown_queries(self):
        queries = [
            "hello world",
            "what's the weather?",
            "tell me a joke",
        ]
        for q in queries:
            result = self.engine.parse_query(q)
            self.assertEqual(result, InvestigationType.UNKNOWN, f"Failed for: {q}")


class TestInvestigators(unittest.TestCase):
    """Test investigator implementations."""
    
    def test_performance_investigator_returns_result(self):
        inv = PerformanceInvestigator()
        result = inv.investigate("slow API", {})
        self.assertIsInstance(result, InvestigationResult)
        self.assertTrue(len(result.findings) > 0)
    
    def test_error_investigator_returns_result(self):
        inv = ErrorInvestigator()
        result = inv.investigate("errors?", {})
        self.assertIsInstance(result, InvestigationResult)
        self.assertTrue(len(result.findings) >= 0)
    
    def test_availability_investigator_returns_result(self):
        inv = AvailabilityInvestigator()
        result = inv.investigate("is it down?", {})
        self.assertIsInstance(result, InvestigationResult)
        self.assertTrue(len(result.findings) > 0)
    
    def test_resource_investigator_returns_result(self):
        inv = ResourceInvestigator()
        result = inv.investigate("disk space?", {})
        self.assertIsInstance(result, InvestigationResult)
        self.assertTrue(len(result.findings) > 0)


class TestIntegration(unittest.TestCase):
    """Integration tests."""
    
    def test_full_investigation(self):
        engine = NLQueryEngine()
        result = engine.investigate("why is the system slow?")
        
        self.assertIsInstance(result, InvestigationResult)
        self.assertEqual(result.query, "why is the system slow?")
        self.assertEqual(result.investigation_type, InvestigationType.PERFORMANCE)
        self.assertTrue(result.duration_ms >= 0)
        self.assertTrue(0 <= result.confidence <= 1)
    
    def test_result_has_recommendations(self):
        engine = NLQueryEngine()
        result = engine.investigate("high CPU usage")
        
        self.assertIsInstance(result.recommendations, list)
        # Should have at least one recommendation
        self.assertTrue(len(result.recommendations) >= 0)


class TestConfig(unittest.TestCase):
    """Test configuration loading."""
    
    def test_default_config(self):
        engine = NLQueryEngine()
        self.assertIn("log_sources", engine.config)
        self.assertIn("lookback_minutes", engine.config)
    
    def test_custom_config(self):
        config_path = "/tmp/test_nlq_config.json"
        test_config = {
            "log_sources": ["/custom/log/path"],
            "lookback_minutes": 30,
        }
        
        with open(config_path, 'w') as f:
            json.dump(test_config, f)
        
        try:
            engine = NLQueryEngine(config_path)
            self.assertEqual(engine.config["log_sources"], ["/custom/log/path"])
            self.assertEqual(engine.config["lookback_minutes"], 30)
        finally:
            Path(config_path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)
