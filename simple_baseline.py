# simple_baseline.py - Clean, effective baseline system

import json

# Simple, data-driven baseline based on actual cybersecurity_intrusion_data.csv analysis
SIMPLE_BASELINE = {
    "legitimate_profile": {
        "failed_logins": {
            "mean": 1.18,
            "std": 0.74,
            "typical_max": 2,  # 95% of legitimate sessions
            "warning_threshold": 3  # Flag if exceeded
        },
        "ip_reputation_score": {
            "mean": 0.30,
            "std": 0.15, 
            "typical_max": 0.60,  # Max observed in legitimate sessions
            "warning_threshold": 0.70  # Clear danger zone
        },
        "login_attempts": {
            "mean": 3.54,
            "std": 1.51,
            "typical_max": 6,  # Max observed in legitimate sessions
            "warning_threshold": 7  # Excessive attempts
        },
        "session_duration": {
            "mean": 763.32,
            "std": 728.18,
            "typical_max": 3000,  # Reasonable upper bound
            "warning_threshold": 5000  # Suspiciously long
        },
        "unusual_time_access": {
            "legitimate_rate": 0.147,  # 14.7% of legitimate sessions
            "attack_rate": 0.153      # 15.3% of attack sessions (not a strong indicator alone)
        }
    },
    
    "attack_indicators": {
        # Clear red flags based on data analysis
        "critical_thresholds": {
            "failed_logins": 4,      # Well above legitimate mean + 2*std (1.18 + 2*0.74 = 2.66)
            "ip_reputation": 0.80,   # Clearly malicious
            "login_attempts": 8,     # Brute force pattern
            "session_duration": 6000 # Unusually long session
        },
        
        # Moderate suspicion levels  
        "warning_thresholds": {
            "failed_logins": 3,      # Above typical legitimate max
            "ip_reputation": 0.70,   # Suspicious reputation
            "login_attempts": 7,     # High attempts
            "session_duration": 4000 # Long session
        },
        
        # Combined risk patterns (multiple moderate flags = high risk)
        "risk_combinations": [
            {"failed_logins": 2, "ip_reputation": 0.50, "description": "Multiple failures + suspicious IP"},
            {"failed_logins": 3, "unusual_time_access": 1, "description": "Failures during off-hours"},
            {"login_attempts": 6, "ip_reputation": 0.60, "description": "High attempts + questionable IP"},
            {"unusual_time_access": 1, "session_duration": 3000, "description": "Off-hours + long session"}
        ]
    }
}

def detect_masquerade_with_baseline(session_data):
    """
    Simple, effective masquerade detection using data-driven baselines
    
    Args:
        session_data (dict): Session data with keys like failed_logins, ip_reputation_score, etc.
    
    Returns:
        dict: Detection result with anomaly flag, confidence, and explanation
    """
    
    baseline = SIMPLE_BASELINE
    legitimate = baseline["legitimate_profile"] 
    indicators = baseline["attack_indicators"]
    
    # Extract session values
    failed_logins = session_data.get('failed_logins', 0)
    ip_reputation = session_data.get('ip_reputation_score', 0.0)
    login_attempts = session_data.get('login_attempts', 1)
    session_duration = session_data.get('session_duration', 0)
    unusual_time = session_data.get('unusual_time_access', 0)
    
    # Detection results
    anomaly_flags = []
    confidence_score = 0.0
    risk_level = "LOW"
    
    # 1. CRITICAL RED FLAGS (immediate high confidence)
    critical = indicators["critical_thresholds"]
    
    if failed_logins >= critical["failed_logins"]:
        anomaly_flags.append(f"🚨 CRITICAL: {failed_logins} failed logins (normal: ≤2)")
        confidence_score += 0.40
        risk_level = "HIGH"
    
    if ip_reputation >= critical["ip_reputation"]:
        anomaly_flags.append(f"🚨 CRITICAL: IP reputation {ip_reputation:.2f} (normal: ≤0.60)")
        confidence_score += 0.45
        risk_level = "HIGH"
    
    if login_attempts >= critical["login_attempts"]:
        anomaly_flags.append(f"🚨 CRITICAL: {login_attempts} login attempts (normal: ≤6)")
        confidence_score += 0.35
        risk_level = "HIGH"
    
    # 2. WARNING LEVEL FLAGS (moderate suspicion)
    warning = indicators["warning_thresholds"]
    
    if failed_logins >= warning["failed_logins"] and failed_logins < critical["failed_logins"]:
        anomaly_flags.append(f"⚠️ WARNING: {failed_logins} failed logins (typical max: 2)")
        confidence_score += 0.20
        if risk_level == "LOW":
            risk_level = "MEDIUM"
    
    if ip_reputation >= warning["ip_reputation"] and ip_reputation < critical["ip_reputation"]:
        anomaly_flags.append(f"⚠️ WARNING: IP reputation {ip_reputation:.2f} (typical max: 0.60)")
        confidence_score += 0.25
        if risk_level == "LOW":
            risk_level = "MEDIUM"
    
    if login_attempts >= warning["login_attempts"] and login_attempts < critical["login_attempts"]:
        anomaly_flags.append(f"⚠️ WARNING: {login_attempts} login attempts (typical max: 6)")
        confidence_score += 0.15
        if risk_level == "LOW":
            risk_level = "MEDIUM"
    
    # 3. STATISTICAL ANOMALY DETECTION (z-score analysis)
    def calculate_z_score(value, mean, std):
        if std == 0:
            return 0
        return abs(value - mean) / std
    
    # Check for statistical outliers (>2 standard deviations)
    failed_z = calculate_z_score(failed_logins, legitimate["failed_logins"]["mean"], legitimate["failed_logins"]["std"])
    ip_z = calculate_z_score(ip_reputation, legitimate["ip_reputation_score"]["mean"], legitimate["ip_reputation_score"]["std"])
    attempts_z = calculate_z_score(login_attempts, legitimate["login_attempts"]["mean"], legitimate["login_attempts"]["std"])
    
    if failed_z > 2.0:
        anomaly_flags.append(f"📊 STATISTICAL: Failed logins {failed_z:.1f}σ from normal")
        confidence_score += 0.15
    
    if ip_z > 2.0:
        anomaly_flags.append(f"📊 STATISTICAL: IP reputation {ip_z:.1f}σ from normal")
        confidence_score += 0.20
    
    if attempts_z > 2.0:
        anomaly_flags.append(f"📊 STATISTICAL: Login attempts {attempts_z:.1f}σ from normal")
        confidence_score += 0.10
    
    # 4. COMBINED RISK PATTERNS
    risk_patterns = indicators["risk_combinations"]
    for pattern in risk_patterns:
        pattern_match = True
        for key, threshold in pattern.items():
            if key == "description":
                continue
            if key == "unusual_time_access":
                if session_data.get(key, 0) < threshold:
                    pattern_match = False
                    break
            else:
                if session_data.get(key, 0) < threshold:
                    pattern_match = False
                    break
        
        if pattern_match:
            anomaly_flags.append(f"🔍 PATTERN: {pattern['description']}")
            confidence_score += 0.25
            if risk_level == "LOW":
                risk_level = "MEDIUM"
    
    # 5. TIME-BASED CONTEXT
    if unusual_time == 1:
        if failed_logins > 0 or ip_reputation > 0.4:
            anomaly_flags.append("🕐 TIMING: Off-hours access with other risk factors")
            confidence_score += 0.20
        else:
            anomaly_flags.append("🕐 TIMING: Off-hours access (low risk)")
            confidence_score += 0.05
    
    # Final decision
    confidence_score = min(1.0, confidence_score)  # Cap at 1.0
    is_anomaly = confidence_score >= 0.3 or len(anomaly_flags) >= 2
    
    # Determine confidence level
    if confidence_score >= 0.7:
        confidence_level = "HIGH"
    elif confidence_score >= 0.4:
        confidence_level = "MEDIUM"
    else:
        confidence_level = "LOW"
    
    return {
        "anomaly": int(is_anomaly),
        "confidence_score": round(confidence_score, 3),
        "confidence_level": confidence_level,
        "risk_level": risk_level,
        "anomaly_flags": anomaly_flags,
        "baseline_comparison": {
            "failed_logins": f"{failed_logins} vs normal {legitimate['failed_logins']['mean']:.1f}±{legitimate['failed_logins']['std']:.1f}",
            "ip_reputation": f"{ip_reputation:.2f} vs normal {legitimate['ip_reputation_score']['mean']:.2f}±{legitimate['ip_reputation_score']['std']:.2f}",
            "login_attempts": f"{login_attempts} vs normal {legitimate['login_attempts']['mean']:.1f}±{legitimate['login_attempts']['std']:.1f}"
        },
        "method_used": "Data-driven Baseline Analysis",
        "explanation": " | ".join(anomaly_flags) if anomaly_flags else "Session appears normal"
    }

# Save the baseline for use in the application
def save_baseline():
    """Save the simple baseline to a JSON file"""
    with open("simple_masquerade_baseline.json", "w") as f:
        json.dump(SIMPLE_BASELINE, f, indent=2)
    print("✅ Simple baseline saved to simple_masquerade_baseline.json")

# Test the detection system
def test_detection():
    """Test cases to validate the detection system"""
    
    test_cases = [
        {
            "name": "Normal User Session",
            "data": {
                "failed_logins": 1,
                "ip_reputation_score": 0.25,
                "login_attempts": 3,
                "session_duration": 600,
                "unusual_time_access": 0
            }
        },
        {
            "name": "Suspicious Activity",
            "data": {
                "failed_logins": 3,
                "ip_reputation_score": 0.75,
                "login_attempts": 7,
                "session_duration": 1200,
                "unusual_time_access": 1
            }
        },
        {
            "name": "Clear Attack",
            "data": {
                "failed_logins": 5,
                "ip_reputation_score": 0.85,
                "login_attempts": 10,
                "session_duration": 300,
                "unusual_time_access": 1
            }
        }
    ]
    
    print("=== TESTING BASELINE DETECTION ===")
    for test in test_cases:
        print(f"\nTest: {test['name']}")
        result = detect_masquerade_with_baseline(test['data'])
        print(f"  Anomaly: {bool(result['anomaly'])}")
        print(f"  Confidence: {result['confidence_level']} ({result['confidence_score']})")
        print(f"  Risk Level: {result['risk_level']}")
        print(f"  Explanation: {result['explanation']}")

if __name__ == "__main__":
    save_baseline()
    test_detection()