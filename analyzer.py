import re 
LOG_FILE = "sample.log"
def analyzer_logs():
    print("=== start of analyzer logs file ===")
    with open(LOG_FILE,'r') as file:
        lines = file.readlines()
        failed_logins = {}
        for line in lines:
            # detection injection sql simple in URL
            if "OR '1'='1" in line or "UNION SELECT" in line:
                print(f"⚠ [ALERTE SQL INJECTION] suspicious request:{line.strip()}")
            #detection de tentative de brute force
            if " 401 " in line:
                ip = line.split()[0]
                failed_logins[ip]=failed_logins.get(ip,0)+1
        for ip, count in failed_logins.items():
            if count >= 5:
                print(f"⚠ [ALERTE BRUTE FORCE] IP {ip} has {count} failed login attempts")
    if __name__ == "__main__":
        analyzer_logs()
