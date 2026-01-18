# Ouick / Normal / High
# Scan profiles
# SCAN_PROFILES = {
#     "Quick": ["-T4", "-F"],
#     "Normal": ["-sV"],
#     "High": ["-sV", "--script", "vuln"]
# }
SCAN_PROFILES = {
    "Quick": "-T4 -F",
    "Normal": "-T4 -sS -sV --top-ports 1000",
    "Deep": "-T3 -sS -sV -p-"
}
