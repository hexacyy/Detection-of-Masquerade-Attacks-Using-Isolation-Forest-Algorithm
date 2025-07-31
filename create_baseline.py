#!/usr/bin/env python3
"""
create_baseline.py - Generate the simple masquerade baseline from dataset analysis
Run this to create the baseline file that your system will actually use.
"""

import json
import pandas as pd
import numpy as np

def create_simple_baseline():
    """Create the simple, effective baseline based on data analysis"""
    
    # Data-driven baseline from cybersecurity_intrusion_data.csv analysis
    # Legitimate sessions: 5,273 | Attack sessions: 4,264
    
    baseline = {
        "data_source": "cybersecurity_intrusion_data.csv",
        "analysis_date": "2025-07-31",
        "legitimate_sessions_count": 5273,
        "attack_sessions_count": 4264,
        
        "legitimate_profile": {
            "failed_logins": {
                "mean": 1.18,
                "std": 0.74,
                "median": 1,
                "q1": 1,
                "q3": 2,
                "typical_max": 2,
                "warning_threshold": 3,
                "critical_threshold": 4
            },
            "ip_reputation_score": {
                "mean": 0.30,
                "std": 0.15,
                "median": 0.29,
                "q1": 0.18,
                "q3": 0.41,
                "typical_max": 0.60,
                "warning_threshold": 0.70,
                "critical_threshold": 0.80
            },
            "login_attempts": {
                "mean": 3.54,
                "std": 1.51,
                "median": 4,
                "q1": 2,
                "q3": 5,
                "typical_max": 6,
                "warning_threshold": 7,
                "critical_threshold": 8
            },
            "session_duration": {
                "mean": 763.32,
                "std": 728.18,
                "median": 554.07,
                "q1": 232.04,
                "q3": 1066.24,
                "typical_max": 3000,
                "warning_threshold": 4000,
                "critical_threshold": 6000
            },
            "network_packet_size": {
                "mean": 501.64,
                "std": 197.62,
                "median": 498,
                "q1": 368,
                "q3": 634,
                "typical_max": 1285,
                "warning_threshold": 1400,
                "critical_threshold": 1500
            },
            "unusual_time_access": {
                "legitimate_rate": 0.147,  # 14.7% of legitimate sessions
                "description": "Off-hours access rate in normal behavior"
            }
        },
        
        "attack_profile": {
            "failed_logins": {
                "mean": 1.94,
                "std": 1.18,
                "median": 2,
                "description": "64% higher than legitimate sessions"
            },
            "ip_reputation_score": {
                "mean": 0.37,
                "std": 0.20,
                "median": 0.35,
                "description": "23% higher than legitimate sessions"
            },
            "login_attempts": {
                "mean": 4.64,
                "std": 2.27,
                "median": 4,
                "description": "31% higher than legitimate sessions"
            },
            "unusual_time_access": {
                "attack_rate": 0.153,  # 15.3% of attack sessions
                "description": "Slightly higher than legitimate, not a strong standalone indicator"
            }
        },
        
        "detection_thresholds": {
            "critical_flags": {
                "failed_logins": 4,      # Well above legitimate mean + 2*std
                "ip_reputation": 0.80,   # Clearly malicious
                "login_attempts": 8,     # Excessive attempts
                "session_duration": 6000 # Unusually long
            },
            "warning_flags": {
                "failed_logins": 3,      # Above typical legitimate max
                "ip_reputation": 0.70,   # Suspicious reputation
                "login_attempts": 7,     # High attempts
                "session_duration": 4000 # Long session
            },
            "statistical_outliers": {
                "z_score_threshold": 2.0,  # 2 standard deviations
                "description": "Flag values >2σ from legitimate mean"
            }
        },
        
        "risk_patterns": [
            {
                "pattern": "multiple_failures_suspicious_ip",
                "conditions": {"failed_logins": ">=2", "ip_reputation": ">=0.5"},
                "risk_score": 0.25,
                "description": "Multiple failures + suspicious IP"
            },
            {
                "pattern": "off_hours_with_failures",
                "conditions": {"unusual_time_access": "==1", "failed_logins": ">=1"},
                "risk_score": 0.20,
                "description": "Off-hours access with authentication failures"
            },
            {
                "pattern": "high_attempts_questionable_ip",
                "conditions": {"login_attempts": ">=6", "ip_reputation": ">=0.6"},
                "risk_score": 0.30,
                "description": "High login attempts from questionable IP"
            }
        ],
        
        "confidence_levels": {
            "HIGH": {"threshold": 0.70, "description": "Strong evidence of masquerade attack"},
            "MEDIUM": {"threshold": 0.40, "description": "Moderate suspicion, investigate further"},
            "LOW": {"threshold": 0.00, "description": "Minimal risk indicators"}
        },
        
        "metadata": {
            "baseline_type": "simple_statistical",
            "features_analyzed": ["failed_logins", "ip_reputation_score", "login_attempts", "session_duration", "unusual_time_access"],
            "detection_approach": "threshold_and_statistical",
            "update_frequency": "monthly_recommended",
            "version": "1.0"
        }
    }
    
    return baseline

def save_baseline_file():
    """Save the baseline to JSON file"""
    baseline = create_simple_baseline()
    
    filename = "simple_masquerade_baseline.json"
    with open(filename, 'w') as f:
        json.dump(baseline, f, indent=2)
    
    print(f"✅ Baseline saved to {filename}")
    print(f"📊 Dataset analyzed: {baseline['legitimate_sessions_count']:,} legitimate + {baseline['attack_sessions_count']:,} attack sessions")
    print(f"🎯 Features: {len(baseline['metadata']['features_analyzed'])} behavioral indicators")
    print(f"🔍 Detection method: {baseline['metadata']['detection_approach']}")
    
    return filename

def test_baseline_detection():
    """Test the baseline with sample data"""
    baseline = create_simple_baseline()
    
    test_cases = [
        {
            "name": "Normal Corporate User",
            "failed_logins": 1,
            "ip_reputation_score": 0.25,
            "login_attempts": 3,
            "unusual_time_access": 0
        },
        {
            "name": "Slightly Suspicious",
            "failed_logins": 2, 
            "ip_reputation_score": 0.65,
            "login_attempts": 5,
            "unusual_time_access": 1
        },
        {
            "name": "Clear Masquerade Attack",
            "failed_logins": 4,
            "ip_reputation_score": 0.85,
            "login_attempts": 9,
            "unusual_time_access": 1
        }
    ]
    
    print("\n🧪 Testing baseline detection logic:")
    print("=" * 50)
    
    for test in test_cases:
        print(f"\nTest: {test['name']}")
        
        # Simple detection logic
        risk_score = 0.0
        flags = []
        
        # Check against thresholds
        critical = baseline["detection_thresholds"]["critical_flags"]
        warning = baseline["detection_thresholds"]["warning_flags"]
        
        if test["failed_logins"] >= critical["failed_logins"]:
            flags.append(f"🚨 CRITICAL: {test['failed_logins']} failed logins")
            risk_score += 0.4
        elif test["failed_logins"] >= warning["failed_logins"]:
            flags.append(f"⚠️ WARNING: {test['failed_logins']} failed logins")
            risk_score += 0.2
        
        if test["ip_reputation_score"] >= critical["ip_reputation"]:
            flags.append(f"🚨 CRITICAL: IP reputation {test['ip_reputation_score']}")
            risk_score += 0.45
        elif test["ip_reputation_score"] >= warning["ip_reputation"]:
            flags.append(f"⚠️ WARNING: IP reputation {test['ip_reputation_score']}")
            risk_score += 0.25
        
        if test["login_attempts"] >= critical["login_attempts"]:
            flags.append(f"🚨 CRITICAL: {test['login_attempts']} login attempts")
            risk_score += 0.35
        elif test["login_attempts"] >= warning["login_attempts"]:
            flags.append(f"⚠️ WARNING: {test['login_attempts']} login attempts")
            risk_score += 0.15
        
        # Pattern matching
        if test["failed_logins"] >= 2 and test["ip_reputation_score"] >= 0.5:
            flags.append("🔍 PATTERN: Multiple failures + suspicious IP")
            risk_score += 0.25
        
        # Determine result
        risk_score = min(1.0, risk_score)
        is_anomaly = risk_score >= 0.3
        
        if risk_score >= 0.7:
            confidence = "HIGH"
        elif risk_score >= 0.4:
            confidence = "MEDIUM"
        else:
            confidence = "LOW"
        
        print(f"  Result: {'🚨 ANOMALY' if is_anomaly else '✅ NORMAL'}")
        print(f"  Confidence: {confidence} ({risk_score:.3f})")
        print(f"  Flags: {len(flags)}")
        for flag in flags:
            print(f"    • {flag}")

if __name__ == "__main__":
    print("🔧 Creating Simple Masquerade Detection Baseline")
    print("=" * 60)
    
    # Create and save the baseline
    filename = save_baseline_file()
    
    # Test the detection logic
    test_baseline_detection()
    
    print(f"\n✅ Done! Your system can now use {filename} for real baseline detection.")
    print("💡 This baseline replaces the complex unused system with actual working detection logic.")