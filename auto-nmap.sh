#!/bin/sh
#
# nmapFullVulnScan.sh - Two-phase scan: discover all open ports, then run
# version detection, default scripts, and vuln scripts on those ports.
#
# Usage: ./nmapFullVulnScan.sh <TARGET> [OUTPUT_DIR]
#
# Phase 1: Full port scan (-p-) to identify all open ports
# Phase 2: On open ports: -sV (version) + -sC (default scripts) + --script vuln
#

# Colors
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

usage() {
    echo
    printf "${RED}Usage: $(basename "$0") ${NC}<TARGET-IP|HOSTNAME>${RED} [OUTPUT_DIR]\n"
    printf "${NC}\n"
    printf "  TARGET     - IP address or hostname to scan\n"
    printf "  OUTPUT_DIR - Optional. Default: <TARGET>/nmap\n"
    printf "\n"
    printf "Phase 1: Scans all 65535 ports to identify open ports\n"
    printf "Phase 2: On open ports runs: version detection, default scripts, vuln scripts\n"
    printf "${NC}\n"
    exit 1
}

# Resolve nmap path
getNmapPath() {
    if type nmap >/dev/null 2>&1; then
        NMAPPATH="$(type nmap | awk '{print $NF}')"
        return 0
    fi
    printf "${RED}Nmap is not installed or not in PATH${NC}\n"
    return 1
}

# Extract open ports from nmap normal output (same format as nmapAutomator assignPorts)
extractOpenPorts() {
    nmap_file="$1"
    if [ ! -f "${nmap_file}" ]; then
        printf "${RED}Port scan output file not found${NC}\n"
        return 1
    fi
    # Lines like "22/tcp   open  ssh" - extract port from first field
    awk -vORS=, -F/ '/^[0-9]/{print $1}' "${nmap_file}" 2>/dev/null | sed 's/.$//'
}

# Validate target
validateTarget() {
    target="$1"
    # IP regex
    if expr "${target}" : '^\([0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\.[0-9]\{1,3\}\)$' >/dev/null; then
        return 0
    fi
    # Hostname (simplified: letters, digits, hyphens, dots)
    if expr "${target}" : '^\(\([[:alnum:]-]\{1,63\}\.\)*[[:alpha:]]\{2,6\}\)$' >/dev/null; then
        return 0
    fi
    return 1
}

main() {
    HOST="$1"
    OUTPUTDIR="${2:-${HOST}}"

    if [ -z "${HOST}" ]; then
        usage
    fi

    if ! validateTarget "${HOST}"; then
        printf "${RED}Invalid target (IP or hostname required)${NC}\n"
        usage
    fi

    if ! getNmapPath; then
        exit 1
    fi

    mkdir -p "${OUTPUTDIR}/nmap"
    cd "${OUTPUTDIR}" || exit 1

    elapsedStart="$(date '+%H:%M:%S' | awk -F: '{print $1 * 3600 + $2 * 60 + $3}')"

    printf "\n${GREEN}===== nmapFullVulnScan: %s =====${NC}\n\n" "${HOST}"

    # --- Phase 1: Full port scan ---
    printf "${GREEN}----- Phase 1: Full port scan (all 65535 ports) -----${NC}\n\n"

    "${NMAPPATH}" -Pn -p- --max-retries 1 --max-rate 500 --max-scan-delay 20 -T4 -v --open \
        -oN "nmap/FullPorts_${HOST}.nmap" \
        "${HOST}"

    openPorts="$(extractOpenPorts "nmap/FullPorts_${HOST}.nmap")"

    if [ -z "${openPorts}" ]; then
        printf "${YELLOW}No open ports found. Exiting.${NC}\n"
        footer "${elapsedStart}"
        exit 0
    fi

    printf "\n${GREEN}Open ports: ${openPorts}${NC}\n\n"

    # --- Phase 2: Version, default scripts, vuln scripts ---
    printf "${GREEN}----- Phase 2: Version + default + vuln scripts on open ports -----${NC}\n\n"

    printf "${YELLOW}Running: -sV -sC --script \"vuln and not vulners\" -p ${openPorts}${NC}\n\n"

    "${NMAPPATH}" -Pn -sV -sC --script "vuln and not vulners" -p"${openPorts}" --open \
        -oN "nmap/VersionScriptVuln_${HOST}.nmap" \
        "${HOST}"

    footer "${elapsedStart}"
}

footer() {
    elapsedStart="$1"
    printf "\n${GREEN}----- Scan complete -----${NC}\n\n"

    elapsedEnd="$(date '+%H:%M:%S' | awk -F: '{print $1 * 3600 + $2 * 60 + $3}')"
    elapsedSeconds=$((elapsedEnd - elapsedStart))

    if [ ${elapsedSeconds} -gt 3600 ]; then
        hours=$((elapsedSeconds / 3600))
        minutes=$(((elapsedSeconds % 3600) / 60))
        seconds=$(((elapsedSeconds % 3600) % 60))
        printf "${YELLOW}Completed in %d hour(s), %d minute(s) and %d second(s)${NC}\n" "${hours}" "${minutes}" "${seconds}"
    elif [ ${elapsedSeconds} -gt 60 ]; then
        minutes=$(((elapsedSeconds % 3600) / 60))
        seconds=$(((elapsedSeconds % 3600) % 60))
        printf "${YELLOW}Completed in %d minute(s) and %d second(s)${NC}\n" "${minutes}" "${seconds}"
    else
        printf "${YELLOW}Completed in %d seconds${NC}\n" "${elapsedSeconds}"
    fi
    printf "${NC}\n"
}

main "$@"
