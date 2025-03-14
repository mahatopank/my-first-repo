import sys

def load_expected_vulnerabilities():
    """Define expected Metasploitable2 vulnerabilities and their keywords"""
    return {
        "VSFTPD 2.3.4 Backdoor (CVE-2011-2523)": [
            "vsftpd 2.3.4", 
            "CVE-2011-2523",
            "backdoor command execution"
        ],
        "UnrealIRCd Backdoor (CVE-2010-2075)": [
            "UnrealIRCd",
            "CVE-2010-2075",
            "backdoor"
        ],
        "Samba username map script Vulnerability (CVE-2007-2447)": [
            "samba 3.0.20",
            "CVE-2007-2447",
            "username map script"
        ],
        "Weak Default Credentials (msfadmin:msfadmin)": [
            "msfadmin",
            "weak credentials",
            "default password"
        ],
        "Apache Tomcat Manager Default Credentials": [
            "tomcat manager",
            "default credentials",
            "admin:admin"
        ],
        "PHP-CGI Vulnerability (CVE-2012-1823)": [
            "php-cgi",
            "CVE-2012-1823",
            "remote code execution"
        ],
        "Telnet Root Login Allowed": [
            "telnet",
            "root login",
            "allowed"
        ],
        "NFS no_root_squash Misconfiguration": [
            "nfs",
            "no_root_squash",
            "misconfiguration"
        ],
        "MySQL Default Credentials": [
            "mysql",
            "root: ",
            "default credentials"
        ],
        "Distcc Daemon Vulnerability (CVE-2004-2687)": [
            "distcc",
            "CVE-2004-2687",
            "remote code execution"
        ]
    }

def audit_report(report_path):
    """Audit the specified report file for Metasploitable2 vulnerabilities"""
    try:
        with open(report_path, 'r') as file:
            content = file.read().lower()
    except FileNotFoundError:
        print(f"Error: Report file '{report_path}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file: {e}")
        sys.exit(1)

    expected_vulns = load_expected_vulnerabilities()
    detected = []
    not_detected = []

    for vuln, keywords in expected_vulns.items():
        found = any(keyword.lower() in content for keyword in keywords)
        if found:
            detected.append(vuln)
        else:
            not_detected.append(vuln)

    return detected, not_detected

def print_results(detected, not_detected):
    """Print the audit results in a readable format"""
    print("\n" + "="*50)
    print("Metasploitable2 Report Audit Summary")
    print("="*50)
    
    print("\n[+] Detected Vulnerabilities:")
    if detected:
        for i, vuln in enumerate(detected, 1):
            print(f"{i}. {vuln}")
    else:
        print("No known vulnerabilities detected")
    
    print("\n[-] Potential Missed Vulnerabilities:")
    if not_detected:
        for i, vuln in enumerate(not_detected, 1):
            print(f"{i}. {vuln}")
    else:
        print("All expected vulnerabilities were detected!")

    print("\n" + "="*50)
    print(f"Total Detected: {len(detected)}")
    print(f"Potential Missed: {len(not_detected)}")
    print("="*50 + "\n")

def main():
    if len(sys.argv) != 2:
        print("Usage: python audit_report.py <path_to_report>")
        sys.exit(1)
    
    report_path = sys.argv[1]
    detected, not_detected = audit_report(report_path)
    print_results(detected, not_detected)

if __name__ == "__main__":
    main()
