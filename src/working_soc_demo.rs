use std::collections::HashMap;
use std::fs;
use tracing::info;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt::init();
    
    info!("🚀 SOC Resilient Log Pipeline Demo - Simplified Version");
    
    // Create directories
    fs::create_dir_all("./demo_logs")?;
    fs::create_dir_all("./demo_output")?;
    
    // Create sample log files
    create_sample_log_files()?;
    
    info!("📊 Starting log ingestion and processing...");
    
    // Simple log processing simulation
    let logs = process_log_files()?;
    
    info!("✅ Successfully processed {} log entries", logs.len());
    
    // Analyze security events
    analyze_security_events(&logs);
    
    // Generate alerts
    generate_security_alerts(&logs);
    
    // Save results
    save_results(&logs)?;
    
    info!("🎯 SOC Pipeline Demo completed successfully!");
    info!("📁 Check the demo_output directory for results");
    
    Ok(())
}

#[derive(Debug, Clone, serde::Serialize)]
struct LogEntry {
    id: String,
    timestamp: String,
    severity: String,
    source: String,
    message: String,
    is_security_event: bool,
}

fn create_sample_log_files() -> Result<(), Box<dyn std::error::Error>> {
    // Sample syslog entries with security events
    let syslog_content = r#"<34>Oct 11 22:14:15 web01 sshd[2342]: Failed password for root from 192.168.1.100 port 22 ssh2
<34>Oct 11 22:14:20 web01 sshd[2342]: Failed password for admin from 192.168.1.100 port 22 ssh2
<34>Oct 11 22:14:25 web01 sshd[2342]: Failed password for user from 192.168.1.100 port 22 ssh2
<165>Oct 11 22:15:01 web01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=192.168.1.200 DST=10.0.0.1 PROTO=TCP SPT=54321 DPT=80
<86>Oct 11 22:15:30 web01 apache2: 192.168.1.50 - - [11/Oct/2024:22:15:30 +0000] "GET /admin/login.php HTTP/1.1" 200 1234
<30>Oct 11 22:16:00 web01 systemd: Started session 123 for user apache.
<13>Oct 11 22:16:15 web01 security: CRITICAL: Potential breach detected in user authentication system
<11>Oct 11 22:16:30 web01 ids: ALERT: Suspicious network activity detected from 192.168.1.200
<12>Oct 11 22:17:00 web01 antivirus: THREAT: Malware detected in file upload.exe
<14>Oct 11 22:17:30 web01 firewall: BLOCK: Port scan attempt from 203.0.113.5
"#;
    
    // Sample security log entries
    let security_content = r#"2024-10-11T22:14:15Z [SECURITY] Failed login attempt for user 'admin' from IP 192.168.1.100
2024-10-11T22:14:20Z [SECURITY] Multiple failed login attempts detected from IP 192.168.1.100
2024-10-11T22:14:25Z [SECURITY] Brute force attack detected from IP 192.168.1.100
2024-10-11T22:15:01Z [SECURITY] Unauthorized access attempt to /admin/config.php
2024-10-11T22:15:30Z [SECURITY] SQL injection attempt detected in parameter 'id'
2024-10-11T22:16:00Z [SECURITY] Privilege escalation attempt by user 'guest'
2024-10-11T22:16:15Z [SECURITY] CRITICAL: Security incident - potential compromise detected
2024-10-11T22:16:30Z [SECURITY] Malware signature detected in uploaded file
2024-10-11T22:17:00Z [SECURITY] Suspicious outbound traffic to known C&C server
2024-10-11T22:17:30Z [SECURITY] Account lockout: user 'admin' after 5 failed attempts
"#;
    
    // Sample firewall log entries
    let firewall_content = r#"2024-10-11T22:14:15Z DENY TCP 192.168.1.200:54321 -> 10.0.0.1:22 (SSH brute force)
2024-10-11T22:14:20Z DENY TCP 192.168.1.200:54322 -> 10.0.0.1:23 (Telnet attempt)
2024-10-11T22:14:25Z DENY TCP 192.168.1.200:54323 -> 10.0.0.1:80 (HTTP flood)
2024-10-11T22:15:01Z BLOCK UDP 203.0.113.1:53 -> 10.0.0.1:53 (DNS amplification)
2024-10-11T22:15:30Z DENY TCP 198.51.100.1:443 -> 10.0.0.1:443 (SSL/TLS attack)
2024-10-11T22:16:00Z BLOCK ICMP 192.0.2.1 -> 10.0.0.1 (Ping of death)
2024-10-11T22:16:15Z DENY TCP 203.0.113.100:80 -> 10.0.0.1:8080 (Port scan)
2024-10-11T22:16:30Z BLOCK TCP 198.51.100.200:3389 -> 10.0.0.1:3389 (RDP intrusion)
2024-10-11T22:17:00Z DENY TCP 10.0.0.50:443 -> 198.51.100.100:443 (Data exfiltration attempt)
2024-10-11T22:17:30Z ALLOW TCP 10.0.0.10:80 -> 192.168.1.50:32451 (Legitimate web traffic)
"#;
    
    // Write sample files
    fs::write("./demo_logs/demo_syslog.log", syslog_content)?;
    fs::write("./demo_logs/demo_security.log", security_content)?;
    fs::write("./demo_logs/demo_firewall.log", firewall_content)?;
    
    info!("📄 Created sample log files with security events");
    Ok(())
}

fn process_log_files() -> Result<Vec<LogEntry>, Box<dyn std::error::Error>> {
    let mut all_logs = Vec::new();
    let mut log_counter = 1;
    
    // Process syslog file
    let syslog_content = fs::read_to_string("./demo_logs/demo_syslog.log")?;
    for line in syslog_content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        
        let log_entry = LogEntry {
            id: format!("LOG-{:04}", log_counter),
            timestamp: extract_timestamp(line),
            severity: extract_severity(line),
            source: "syslog".to_string(),
            message: line.to_string(),
            is_security_event: is_security_event(line),
        };
        
        all_logs.push(log_entry);
        log_counter += 1;
    }
    
    // Process security log file
    let security_content = fs::read_to_string("./demo_logs/demo_security.log")?;
    for line in security_content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        
        let log_entry = LogEntry {
            id: format!("LOG-{:04}", log_counter),
            timestamp: extract_timestamp(line),
            severity: "HIGH".to_string(),
            source: "security".to_string(),
            message: line.to_string(),
            is_security_event: true,
        };
        
        all_logs.push(log_entry);
        log_counter += 1;
    }
    
    // Process firewall log file
    let firewall_content = fs::read_to_string("./demo_logs/demo_firewall.log")?;
    for line in firewall_content.lines() {
        if line.trim().is_empty() {
            continue;
        }
        
        let log_entry = LogEntry {
            id: format!("LOG-{:04}", log_counter),
            timestamp: extract_timestamp(line),
            severity: determine_firewall_severity(line),
            source: "firewall".to_string(),
            message: line.to_string(),
            is_security_event: is_firewall_security_event(line),
        };
        
        all_logs.push(log_entry);
        log_counter += 1;
    }
    
    Ok(all_logs)
}

fn extract_timestamp(line: &str) -> String {
    // Simple timestamp extraction
    if line.starts_with('<') {
        // Syslog format
        if let Some(start) = line.find('>') {
            let after_priority = &line[start + 1..];
            if let Some(end) = after_priority.find(' ') {
                let timestamp_part = &after_priority[..end + 16]; // Extract approx timestamp
                return timestamp_part.trim().to_string();
            }
        }
    } else if line.contains('T') && line.contains('Z') {
        // ISO format
        if let Some(end) = line.find('Z') {
            return line[..end + 1].to_string();
        }
    }
    
    "unknown".to_string()
}

fn extract_severity(line: &str) -> String {
    if line.contains("CRITICAL") || line.contains("ALERT") {
        "CRITICAL".to_string()
    } else if line.contains("Failed") || line.contains("BLOCK") || line.contains("DENY") {
        "HIGH".to_string()
    } else if line.contains("THREAT") || line.contains("attack") {
        "MEDIUM".to_string()
    } else {
        "INFO".to_string()
    }
}

fn determine_firewall_severity(line: &str) -> String {
    if line.contains("BLOCK") || line.contains("DENY") {
        "HIGH".to_string()
    } else if line.contains("ALLOW") {
        "INFO".to_string()
    } else {
        "MEDIUM".to_string()
    }
}

fn is_security_event(line: &str) -> bool {
    let security_keywords = [
        "Failed password", "CRITICAL", "ALERT", "THREAT", "BLOCK",
        "attack", "breach", "malware", "intrusion", "suspicious"
    ];
    
    security_keywords.iter().any(|keyword| line.to_lowercase().contains(&keyword.to_lowercase()))
}

fn is_firewall_security_event(line: &str) -> bool {
    line.contains("DENY") || line.contains("BLOCK") || 
    line.contains("brute force") || line.contains("intrusion")
}

fn analyze_security_events(logs: &[LogEntry]) {
    let security_events: Vec<_> = logs.iter().filter(|log| log.is_security_event).collect();
    
    info!("📈 Security Event Analysis:");
    info!("   Total logs processed: {}", logs.len());
    info!("   Security events detected: {}", security_events.len());
    
    // Count by severity
    let mut severity_counts = HashMap::new();
    for log in &security_events {
        *severity_counts.entry(log.severity.clone()).or_insert(0) += 1;
    }
    
    info!("   Security events by severity:");
    for (severity, count) in severity_counts {
        info!("     {}: {}", severity, count);
    }
    
    // Count by source
    let mut source_counts = HashMap::new();
    for log in &security_events {
        *source_counts.entry(log.source.clone()).or_insert(0) += 1;
    }
    
    info!("   Security events by source:");
    for (source, count) in source_counts {
        info!("     {}: {}", source, count);
    }
    
    // Show top security events
    info!("   Top security events:");
    for (i, event) in security_events.iter().take(5).enumerate() {
        info!("     {}. {} - {} [{}]", 
            i + 1, 
            event.id, 
            event.message.chars().take(80).collect::<String>(),
            event.severity
        );
    }
}

fn generate_security_alerts(logs: &[LogEntry]) {
    info!("🚨 Generating Security Alerts:");
    
    let mut alert_counter = 1;
    
    // Check for failed login patterns
    let failed_logins: Vec<_> = logs.iter()
        .filter(|log| log.message.to_lowercase().contains("failed password"))
        .collect();
    
    if failed_logins.len() > 2 {
        info!("   ALERT-{:03}: Brute Force Attack Detected", alert_counter);
        info!("     Severity: CRITICAL");
        info!("     Description: {} failed login attempts detected", failed_logins.len());
        info!("     Recommendation: Block source IP and investigate");
        alert_counter += 1;
    }
    
    // Check for critical security incidents
    let critical_events: Vec<_> = logs.iter()
        .filter(|log| log.message.to_lowercase().contains("critical") || 
                      log.message.to_lowercase().contains("breach"))
        .collect();
    
    if !critical_events.is_empty() {
        info!("   ALERT-{:03}: Critical Security Incident", alert_counter);
        info!("     Severity: EMERGENCY");
        info!("     Description: {} critical security incidents detected", critical_events.len());
        info!("     Recommendation: Immediate investigation required");
        alert_counter += 1;
    }
    
    // Check for malware detection
    let malware_events: Vec<_> = logs.iter()
        .filter(|log| log.message.to_lowercase().contains("malware") ||
                      log.message.to_lowercase().contains("threat"))
        .collect();
    
    if !malware_events.is_empty() {
        info!("   ALERT-{:03}: Malware Detection", alert_counter);
        info!("     Severity: HIGH");
        info!("     Description: {} malware threats detected", malware_events.len());
        info!("     Recommendation: Quarantine affected systems");
        alert_counter += 1;
    }
    
    // Check for network attacks
    let network_attacks: Vec<_> = logs.iter()
        .filter(|log| log.message.contains("BLOCK") || log.message.contains("DENY"))
        .collect();
    
    if network_attacks.len() > 5 {
        info!("   ALERT-{:03}: Network Attack Pattern", alert_counter);
        info!("     Severity: HIGH");
        info!("     Description: {} blocked network connections", network_attacks.len());
        info!("     Recommendation: Review firewall rules and investigate source IPs");
    }
}

fn save_results(logs: &[LogEntry]) -> Result<(), Box<dyn std::error::Error>> {
    // Create JSON output
    let json_output = serde_json::to_string_pretty(logs)?;
    fs::write("./demo_output/processed_logs.json", json_output)?;
    
    // Create CSV summary
    let mut csv_content = "ID,Timestamp,Severity,Source,IsSecurityEvent,Message\n".to_string();
    for log in logs {
        csv_content.push_str(&format!(
            "{},{},{},{},{},\"{}\"\n",
            log.id,
            log.timestamp,
            log.severity,
            log.source,
            log.is_security_event,
            log.message.replace("\"", "\\\"")
        ));
    }
    fs::write("./demo_output/log_summary.csv", csv_content)?;
    
    // Create security events report
    let security_events: Vec<_> = logs.iter().filter(|log| log.is_security_event).collect();
    let security_report = format!(
        "SOC SECURITY REPORT\n==================\n\n\
        Total Logs Processed: {}\n\
        Security Events: {}\n\
        Security Event Rate: {:.1}%\n\n\
        SECURITY EVENTS:\n{}\n",
        logs.len(),
        security_events.len(),
        (security_events.len() as f64 / logs.len() as f64) * 100.0,
        security_events.iter()
            .map(|event| format!("{} [{}] {}", event.id, event.severity, event.message))
            .collect::<Vec<_>>()
            .join("\n")
    );
    fs::write("./demo_output/security_report.txt", security_report)?;
    
    info!("💾 Output files created:");
    info!("   - ./demo_output/processed_logs.json (structured data)");
    info!("   - ./demo_output/log_summary.csv (spreadsheet format)");
    info!("   - ./demo_output/security_report.txt (security analysis)");
    
    Ok(())
}
