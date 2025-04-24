#!/bin/bash
#
# PHP Hack Detection Script
# This script scans web directories for PHP injections, backdoors, and other common hack patterns
# It detects suspicious PHP functions, base64-encoded payloads, unusual file permissions, 
# malicious cron jobs, and .htaccess modifications
# by Denis (BeforeMyCompileFails) 2025
#

# ANSI color codes for better output readability
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Initialize counters and arrays
TOTAL_SCANNED=0
SUSPICIOUS_FILES=()
MODIFIED_FILES=()
BACKDOOR_FILES=()
WRITABLE_DIRS=()
CRON_ISSUES=()
HTACCESS_ISSUES=()

# Default scan directory is current directory
SCAN_DIR="."
LOG_FILE="php_hack_scan_$(date +%Y%m%d_%H%M%S).log"
VERBOSE=0
USE_CLAMAV=1
DAYS_TO_CHECK=7
THOROUGH=0

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------

show_banner() {
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                 ${GREEN}PHP HACK DETECTION SCRIPT${BLUE}                 ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo -e "${CYAN}Scanning for PHP backdoors, injections, and suspicious patterns${NC}"
    echo ""
}

usage() {
    echo -e "${GREEN}Usage:${NC} $0 [options]"
    echo 
    echo -e "${GREEN}Options:${NC}"
    echo "  -d, --directory DIR    Directory to scan (default: current directory)"
    echo "  -l, --log FILE         Log file (default: php_hack_scan_DATE.log)"
    echo "  -t, --days DAYS        Check files modified in the last DAYS days (default: 7)"
    echo "  -n, --no-clamav        Skip ClamAV scan even if available"
    echo "  -v, --verbose          Show detailed output"
    echo "  -T, --thorough         Perform thorough (but slower) scans"
    echo "  -h, --help             Display this help message"
    echo
    exit 1
}

log_message() {
    local level=$1
    local message=$2
    
    # Always write to log file
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] [${level}] ${message}" >> "$LOG_FILE"
    
    # Print to console based on level and verbosity
    case $level in
        "INFO")
            if [ $VERBOSE -eq 1 ]; then
                echo -e "${GREEN}[INFO]${NC} ${message}"
            fi
            ;;
        "WARNING")
            echo -e "${YELLOW}[WARNING]${NC} ${message}"
            ;;
        "ALERT")
            echo -e "${RED}[ALERT]${NC} ${message}"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} ${message}"
            ;;
    esac
}

cleanup() {
    log_message "INFO" "Scan interrupted. Cleaning up..."
    exit 1
}

spinner() {
    local pid=$1
    local delay=0.1
    local spinstr='|/-\'
    while [ "$(ps a | awk '{print $1}' | grep $pid)" ]; do
        local temp=${spinstr#?}
        printf " [%c]  " "$spinstr"
        local spinstr=$temp${spinstr%"$temp"}
        sleep $delay
        printf "\b\b\b\b\b\b"
    done
    printf "    \b\b\b\b"
}

check_command() {
    command -v "$1" >/dev/null 2>&1
}

# -----------------------------------------------------------------------------
# Scanning Functions
# -----------------------------------------------------------------------------

check_suspicious_php_functions() {
    log_message "INFO" "Checking for suspicious PHP functions in directory: $SCAN_DIR"
    echo -e "\n${CYAN}Checking for suspicious PHP functions...${NC}"
    
    # Suspicious PHP functions to check for
    local suspicious_functions=(
        "eval(" "base64_decode(" "gzinflate(" "gzuncompress(" "str_rot13("
        "system(" "exec(" "shell_exec(" "passthru(" "popen("
        "proc_open(" "pcntl_exec(" "assert(" "preg_replace.*\/e" "create_function("
        "include(" "include_once(" "require(" "require_once(" "file_get_contents("
        "readfile(" "fopen(" "file(" "fread(" "file_put_contents("
        "move_uploaded_file(" "curl_exec(" "curl_init(" "fsockopen(" "pfsockopen("
        "stream_socket_client(" "php_uname(" "chmod(" "chown(" "copy("
        "unlink(" "rmdir(" "mkdir(" "rename(" "touch("
        "symlink(" "phpinfo(" "posix_" "apache_setenv(" "putenv("
        "ini_" "set_time_limit(" "highlight_file(" "show_source("
        "ob_start(" "\\x[0-9a-fA-F]\\{2\\}" "\\u[0-9a-fA-F]\\{4\\}"
    )
    
    total_found=0
    
    # Create search pattern for grep
    local pattern=$(IFS="|"; echo "${suspicious_functions[*]}")
    
    # Find all PHP files and check for suspicious functions
    find "$SCAN_DIR" -type f -name "*.php" -o -name "*.phtml" -o -name "*.inc" | while read -r file; do
        TOTAL_SCANNED=$((TOTAL_SCANNED+1))
        
        # Skip files larger than 10MB to avoid excessive processing
        if [ "$(stat -c%s "$file")" -gt 10485760 ]; then
            log_message "INFO" "Skipping large file: $file (file size > 10MB)"
            continue
        fi
        
        # Check for suspicious PHP functions
        matches=$(grep -l -E "$pattern" "$file" 2>/dev/null)
        
        if [ -n "$matches" ]; then
            # Do a more thorough check to reduce false positives
            # Check for combinations of suspicious patterns or obfuscation techniques
            obfuscated=$(grep -l -E '(\$[a-zA-Z0-9_]+\(|chr\(|\\x[0-9a-fA-F]{2}|base64_decode|eval.*\()' "$file" 2>/dev/null)
            
            if [ -n "$obfuscated" ] || [ $THOROUGH -eq 1 ]; then
                BACKDOOR_FILES+=("$file")
                suspicious_content=$(grep -n -E "$pattern" "$file" | head -5)
                log_message "ALERT" "Possible backdoor in $file:"
                log_message "ALERT" "$(echo "$suspicious_content" | sed 's/^/  /')"
                total_found=$((total_found+1))
                
                # Extract specific suspicious functions found
                for func in "${suspicious_functions[@]}"; do
                    if grep -q "$func" "$file" 2>/dev/null; then
                        log_message "INFO" "Found suspicious function: $func in $file"
                    fi
                done
            fi
        fi
    done
    
    echo -e "${YELLOW}Found ${total_found} files with suspicious PHP functions${NC}"
}

check_base64_encoded_content() {
    log_message "INFO" "Checking for base64 encoded content in PHP files"
    echo -e "\n${CYAN}Checking for base64 encoded payloads...${NC}"
    
    total_found=0
    
    # Find all PHP files and check for base64 encoded content
    find "$SCAN_DIR" -type f -name "*.php" -o -name "*.phtml" -o -name "*.inc" | while read -r file; do
        # Skip files larger than 10MB
        if [ "$(stat -c%s "$file")" -gt 10485760 ]; then
            continue
        fi
        
        # Check for base64 encoded strings (longer than 100 chars to reduce false positives)
        base64_content=$(grep -o -E "(base64_decode\\(['\"]([-A-Za-z0-9+/]{100,})['\"]\\))" "$file" 2>/dev/null)
        
        # Also look for direct long base64 strings
        if [ -z "$base64_content" ]; then
            base64_content=$(grep -o -E "['\"]([-A-Za-z0-9+/]{100,})['\"]" "$file" 2>/dev/null)
        fi
        
        if [ -n "$base64_content" ]; then
            # Verify if it looks like a real base64 string (correct characters and length divisible by 4)
            if echo "$base64_content" | grep -q -E "^[-A-Za-z0-9+/=]+$"; then
                SUSPICIOUS_FILES+=("$file")
                log_message "ALERT" "Found base64 encoded content in $file"
                
                if [ $VERBOSE -eq 1 ]; then
                    # Try to decode a sample of the base64 content
                    sample=$(echo "$base64_content" | head -1 | cut -c1-100)
                    decoded=$(echo "$sample" | base64 -d 2>/dev/null | xxd -p | head -c 100)
                    log_message "INFO" "Sample decoded (hex): $decoded"
                fi
                
                total_found=$((total_found+1))
            fi
        fi
    done
    
    echo -e "${YELLOW}Found ${total_found} files with suspicious base64 encoded content${NC}"
}

check_recent_file_changes() {
    log_message "INFO" "Checking for recently modified files (last $DAYS_TO_CHECK days)"
    echo -e "\n${CYAN}Checking for recently modified files (last $DAYS_TO_CHECK days)...${NC}"
    
    total_found=0
    
    # Find files modified in the last N days
    find "$SCAN_DIR" -type f -mtime -"$DAYS_TO_CHECK" | grep -E '\.(php|phtml|inc|htaccess)$' | while read -r file; do
        # Get file modification time
        mod_time=$(stat -c %y "$file")
        MODIFIED_FILES+=("$file")
        
        log_message "INFO" "Recently modified file: $file (Modified: $mod_time)"
        total_found=$((total_found+1))
    done
    
    echo -e "${YELLOW}Found ${total_found} recently modified PHP files${NC}"
}

check_writable_directories() {
    log_message "INFO" "Checking for writable directories and unexpected PHP files"
    echo -e "\n${CYAN}Checking for writable directories and unexpected PHP files...${NC}"
    
    # Common upload/writable directories to check
    local writable_dirs=(
        "wp-content/uploads"
        "wp-content/cache"
        "wp-content/themes"
        "wp-content/plugins"
        "uploads"
        "images"
        "cache"
        "tmp"
        "temp"
    )
    
    total_found=0
    
    # Check each potential writable directory
    for dir in "${writable_dirs[@]}"; do
        if [ -d "$SCAN_DIR/$dir" ]; then
            # Check if directory is writable
            if [ -w "$SCAN_DIR/$dir" ]; then
                WRITABLE_DIRS+=("$SCAN_DIR/$dir")
                log_message "WARNING" "Directory is writable: $SCAN_DIR/$dir"
                
                # Check for PHP files in writable directories
                php_files=$(find "$SCAN_DIR/$dir" -type f -name "*.php" 2>/dev/null)
                
                if [ -n "$php_files" ]; then
                    log_message "ALERT" "Found PHP files in writable directory $SCAN_DIR/$dir:"
                    echo "$php_files" | while read -r file; do
                        log_message "ALERT" "  - $file"
                        SUSPICIOUS_FILES+=("$file")
                        total_found=$((total_found+1))
                    done
                fi
            fi
        fi
    done
    
    echo -e "${YELLOW}Found ${total_found} suspicious PHP files in writable directories${NC}"
}

check_htaccess_files() {
    log_message "INFO" "Checking for suspicious .htaccess modifications"
    echo -e "\n${CYAN}Checking for suspicious .htaccess modifications...${NC}"
    
    total_found=0
    
    # Find all .htaccess files
    find "$SCAN_DIR" -type f -name ".htaccess" | while read -r file; do
        # Check for suspicious content in .htaccess files
        suspicious=$(grep -E 'RewriteRule|AddHandler|SetHandler|php_value|auto_prepend_file|auto_append_file|allow_url_include|base64' "$file" 2>/dev/null)
        
        if [ -n "$suspicious" ]; then
            HTACCESS_ISSUES+=("$file")
            log_message "ALERT" "Suspicious .htaccess file: $file"
            log_message "ALERT" "Suspicious content:"
            log_message "ALERT" "$(echo "$suspicious" | sed 's/^/  /')"
            total_found=$((total_found+1))
        fi
    done
    
    echo -e "${YELLOW}Found ${total_found} suspicious .htaccess files${NC}"
}

check_cron_jobs() {
    log_message "INFO" "Checking for suspicious cron jobs"
    echo -e "\n${CYAN}Checking for suspicious cron jobs...${NC}"
    
    total_found=0
    
    # Only check crontabs if we have permission
    if check_command "crontab"; then
        # Check for suspicious content in user's crontab
        user_cron=$(crontab -l 2>/dev/null)
        
        if [ -n "$user_cron" ]; then
            suspicious=$(echo "$user_cron" | grep -E 'curl|wget|eval|base64|php|\?|http|\|' 2>/dev/null)
            
            if [ -n "$suspicious" ]; then
                CRON_ISSUES+=("user_crontab")
                log_message "ALERT" "Suspicious user crontab entries:"
                log_message "ALERT" "$(echo "$suspicious" | sed 's/^/  /')"
                total_found=$((total_found+1))
            fi
        fi
        
        # Check system-wide cron jobs if we have root access
        if [ "$(id -u)" -eq 0 ]; then
            # Check /etc/crontab
            if [ -f /etc/crontab ]; then
                suspicious=$(grep -E 'curl|wget|eval|base64|php|\?|http|\|' /etc/crontab 2>/dev/null)
                
                if [ -n "$suspicious" ]; then
                    CRON_ISSUES+=("/etc/crontab")
                    log_message "ALERT" "Suspicious entries in /etc/crontab:"
                    log_message "ALERT" "$(echo "$suspicious" | sed 's/^/  /')"
                    total_found=$((total_found+1))
                fi
            fi
            
            # Check /etc/cron.d directory
            if [ -d /etc/cron.d ]; then
                find /etc/cron.d -type f | while read -r cron_file; do
                    suspicious=$(grep -E 'curl|wget|eval|base64|php|\?|http|\|' "$cron_file" 2>/dev/null)
                    
                    if [ -n "$suspicious" ]; then
                        CRON_ISSUES+=("$cron_file")
                        log_message "ALERT" "Suspicious entries in $cron_file:"
                        log_message "ALERT" "$(echo "$suspicious" | sed 's/^/  /')"
                        total_found=$((total_found+1))
                    fi
                done
            fi
        else
            log_message "INFO" "Not running as root, skipping system cron job checks"
        fi
    else
        log_message "INFO" "Crontab command not available, skipping cron checks"
    fi
    
    echo -e "${YELLOW}Found ${total_found} suspicious cron job entries${NC}"
}

check_unusual_file_permissions() {
    log_message "INFO" "Checking for unusual file permissions"
    echo -e "\n${CYAN}Checking for unusual file permissions...${NC}"
    
    total_found=0
    
    # Find files with unusual permissions (world-writable or SUID/SGID)
    find "$SCAN_DIR" -type f \( -perm -2 -o -perm -4000 -o -perm -2000 \) | grep -E '\.(php|phtml|inc)$' | while read -r file; do
        perms=$(stat -c "%a %A" "$file")
        SUSPICIOUS_FILES+=("$file")
        log_message "ALERT" "File with suspicious permissions: $file ($perms)"
        total_found=$((total_found+1))
    done
    
    echo -e "${YELLOW}Found ${total_found} files with unusual permissions${NC}"
}

run_clamav_scan() {
    log_message "INFO" "Checking for ClamAV availability"
    echo -e "\n${CYAN}Checking for ClamAV...${NC}"
    
    if [ "$USE_CLAMAV" -eq 0 ]; then
        log_message "INFO" "ClamAV scan disabled by user"
        echo -e "${YELLOW}ClamAV scan disabled by user${NC}"
        return
    fi
    
    if check_command "clamscan"; then
        log_message "INFO" "ClamAV found, running virus scan on $SCAN_DIR"
        echo -e "${GREEN}ClamAV found! Running virus scan...${NC}"
        
        # Create a temporary file for ClamAV results
        clam_results=$(mktemp)
        
        # Run ClamAV scan in background
        clamscan -r --infected --no-summary "$SCAN_DIR" > "$clam_results" 2>&1 &
        local pid=$!
        
        # Show spinner while ClamAV is running
        echo -ne "${YELLOW}Scanning with ClamAV... "
        spinner $pid
        echo -e "${GREEN}Done!${NC}"
        
        # Process ClamAV results
        if [ -s "$clam_results" ]; then
            detected=$(cat "$clam_results" | wc -l)
            log_message "ALERT" "ClamAV detected $detected infected files!"
            log_message "ALERT" "ClamAV results:"
            log_message "ALERT" "$(cat "$clam_results" | sed 's/^/  /')"
            echo -e "${RED}ClamAV detected $detected infected files!${NC}"
            cat "$clam_results"
        else
            log_message "INFO" "ClamAV did not detect any malware"
            echo -e "${GREEN}ClamAV did not detect any malware${NC}"
        fi
        
        # Clean up
        rm -f "$clam_results"
    else
        log_message "INFO" "ClamAV not installed, skipping virus scan"
        echo -e "${YELLOW}ClamAV not installed. Consider installing for better detection.${NC}"
        echo -e "${YELLOW}  sudo apt-get install clamav${NC} (Debian/Ubuntu)"
        echo -e "${YELLOW}  sudo yum install clamav${NC} (CentOS/RHEL)"
    fi
}

check_hidden_files() {
    log_message "INFO" "Checking for hidden files and directories"
    echo -e "\n${CYAN}Checking for suspicious hidden files...${NC}"
    
    total_found=0
    
    # Find hidden files with PHP extension or content
    find "$SCAN_DIR" -type f -name ".*" | while read -r file; do
        # Check if it's a PHP file either by extension or by content
        if [[ "$file" == *.php ]] || grep -q "<?php" "$file" 2>/dev/null; then
            SUSPICIOUS_FILES+=("$file")
            log_message "ALERT" "Hidden PHP file found: $file"
            total_found=$((total_found+1))
        fi
    done
    
    echo -e "${YELLOW}Found ${total_found} suspicious hidden files${NC}"
}

check_web_shells() {
    log_message "INFO" "Checking for known web shells and backdoors"
    echo -e "\n${CYAN}Checking for known web shells and backdoors...${NC}"
    
    total_found=0
    
    # Common web shell signatures
    local signatures=(
        "c99shell"
        "r57shell"
        "WSO"
        "FilesMan"
        "b374k"
        "weevely"
        "indoxploit"
        "Alfa"
        "AnonymousFox"
        "bypass"
        "backdoor"
        "rootkit"
        "\/\/uname -a"
        "FilesMan"
        "eval(base64_decode"
        "eval(\"\\\\x"
        "system(base64_decode"
        "md5(chr(112).chr(97).chr(115).chr(115))"
        "preg_replace(\"\/.+\/e\""
        "shell_exec"
        "webshell"
        "passthru"
        "symlink"
        "\\\$_POST\['cmd'\]"
        "\\\$_GET\['cmd'\]"
        "phpinfo"
        "\\\$GLOBALS\['\\\x"
        "str_rot13"
        "\\\\x[0-9a-fA-F]{2}\\\\x[0-9a-fA-F]{2}"
    )
    
    # Create search pattern for grep
    local pattern=$(IFS="|"; echo "${signatures[*]}")
    
    # Find all PHP files and check for web shell signatures
    find "$SCAN_DIR" -type f -name "*.php" -o -name "*.phtml" -o -name "*.inc" | while read -r file; do
        # Skip files larger than 10MB
        if [ "$(stat -c%s "$file")" -gt 10485760 ]; then
            continue
        fi
        
        # Check for web shell signatures
        matches=$(grep -l -E "$pattern" "$file" 2>/dev/null)
        
        if [ -n "$matches" ]; then
            BACKDOOR_FILES+=("$file")
            log_message "ALERT" "Possible web shell detected: $file"
            
            # Find which signature matched
            for sig in "${signatures[@]}"; do
                if grep -q "$sig" "$file" 2>/dev/null; then
                    log_message "INFO" "Matched signature: $sig"
                fi
            done
            
            total_found=$((total_found+1))
        fi
    done
    
    echo -e "${YELLOW}Found ${total_found} potential web shells${NC}"
}

check_iframes_redirects() {
    log_message "INFO" "Checking for malicious iframes and redirects"
    echo -e "\n${CYAN}Checking for malicious iframes and redirects...${NC}"
    
    total_found=0
    
    # Find all PHP, HTML, and JS files
    find "$SCAN_DIR" -type f \( -name "*.php" -o -name "*.html" -o -name "*.htm" -o -name "*.js" \) | while read -r file; do
        # Skip files larger than 10MB
        if [ "$(stat -c%s "$file")" -gt 10485760 ]; then
            continue
        fi
        
        # Check for suspicious iframes
        iframe_check=$(grep -E '<iframe.*src=.*style="display:none|<iframe.*opacity:0|<iframe.*height:0|<iframe.*width:0' "$file" 2>/dev/null)
        
        # Check for suspicious redirects
        redirect_check=$(grep -E 'window\.location|document\.location|location\.href|location\.replace|setTimeout\(.*location' "$file" 2>/dev/null)
        
        if [ -n "$iframe_check" ] || [ -n "$redirect_check" ]; then
            SUSPICIOUS_FILES+=("$file")
            
            if [ -n "$iframe_check" ]; then
                log_message "ALERT" "Hidden iframe detected in $file:"
                log_message "ALERT" "$(echo "$iframe_check" | sed 's/^/  /')"
            fi
            
            if [ -n "$redirect_check" ]; then
                log_message "ALERT" "Suspicious redirect detected in $file:"
                log_message "ALERT" "$(echo "$redirect_check" | sed 's/^/  /')"
            fi
            
            total_found=$((total_found+1))
        fi
    done
    
    echo -e "${YELLOW}Found ${total_found} files with suspicious iframes or redirects${NC}"
}

check_wp_integrity() {
    log_message "INFO" "Checking for WordPress core integrity (if applicable)"
    echo -e "\n${CYAN}Checking WordPress core integrity (if applicable)...${NC}"
    
    # Check if this is a WordPress installation
    if [ -f "$SCAN_DIR/wp-config.php" ]; then
        log_message "INFO" "WordPress installation detected, checking core files"
        echo -e "${GREEN}WordPress installation detected!${NC}"
        
        # Check for common WordPress file modifications
        wp_core_files=(
            "wp-login.php"
            "wp-includes/general-template.php"
            "wp-includes/formatting.php"
            "wp-includes/functions.php"
            "wp-includes/load.php"
            "wp-includes/plugin.php"
            "wp-includes/post.php"
            "wp-includes/user.php"
            "wp-admin/admin.php"
        )
        
        total_found=0
        
        for file in "${wp_core_files[@]}"; do
            if [ -f "$SCAN_DIR/$file" ]; then
                # Check for suspicious functions in core files
                suspicious=$(grep -E 'eval\(|base64_decode\(|gzinflate\(|str_rot13\(|system\(|exec\(|passthru\(|shell_exec\(' "$SCAN_DIR/$file" 2>/dev/null)
                
                if [ -n "$suspicious" ]; then
                    BACKDOOR_FILES+=("$SCAN_DIR/$file")
                    log_message "ALERT" "WordPress core file potentially compromised: $SCAN_DIR/$file"
                    log_message "ALERT" "Suspicious content:"
                    log_message "ALERT" "$(echo "$suspicious" | sed 's/^/  /')"
                    total_found=$((total_found+1))
                fi
            fi
        done
        
        echo -e "${YELLOW}Found ${total_found} potentially compromised WordPress core files${NC}"
        
        # Check for suspicious user accounts if we can access the database
        if [ -f "$SCAN_DIR/wp-config.php" ] && check_command "wp" && [ "$(which php 2>/dev/null)" != "" ]; then
            log_message "INFO" "WP-CLI found, checking for suspicious admin users"
            echo -e "${GREEN}WP-CLI found, checking for suspicious admin users...${NC}"
            
            # Try to run WP-CLI to list users (might fail if no access)
            wp_users=$(cd "$SCAN_DIR" && wp user list --role=administrator --fields=ID,user_login,user_registered --format=csv 2>/dev/null)
            
            if [ -n "$wp_users" ]; then
                log_message "INFO" "WordPress administrators:"
                log_message "INFO" "$wp_users"
                
                # Check for recently added admin users (last 30 days)
                recent_date=$(date -d "30 days ago" +%Y-%m-%d)
                recent_admins=$(echo "$wp_users" | grep -v "ID,user_login,user_registered" | awk -F',' -v date="$recent_date" '$3 >= date {print $0}')
                
                if [ -n "$recent_admins" ]; then
                    log_message "ALERT" "Recently added WordPress admin accounts (potential backdoor):"
                    log_message "ALERT" "$(echo "$recent_admins" | sed 's/^/  /')"
                    echo -e "${RED}Found recently added WordPress admin accounts:${NC}"
                    echo -e "${RED}$(echo "$recent_admins" | sed 's/^/  /')${NC}"
                fi
            else
                log_message "INFO" "Could not check WordPress users (WP-CLI failed or no access)"
            fi
        fi
    else
        log_message "INFO" "No WordPress installation detected, skipping WP integrity checks"
        echo -e "${YELLOW}No WordPress installation detected, skipping WP integrity checks${NC}"
    fi
}

# -----------------------------------------------------------------------------
# Main Function
# -----------------------------------------------------------------------------

main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--directory)
                SCAN_DIR="$2"
                shift 2
                ;;
            -l|--log)
                LOG_FILE="$2"
                shift 2
                ;;
            -t|--days)
                DAYS_TO_CHECK="$2"
                shift 2
                ;;
            -n|--no-clamav)
                USE_CLAMAV=0
                shift
                ;;
            -v|--verbose)
                VERBOSE=1
                shift
                ;;
            -T|--thorough)
                THOROUGH=1
                shift
                ;;
            -h|--help)
                usage
                ;;
            *)
                echo -e "${RED}Unknown option: $1${NC}"
                usage
                ;;
        esac
    done
    
    # Validate scan directory
    if [ ! -d "$SCAN_DIR" ]; then
        echo -e "${RED}Error: Directory '$SCAN_DIR' does not exist${NC}"
        exit 1
    fi
    
    # Setup trap for clean exit
    trap cleanup SIGINT SIGTERM
    
    # Show banner
    show_banner
    
    # Start log file
    echo "PHP Hack Detection Scan - $(date)" > "$LOG_FILE"
    echo "Scan directory: $SCAN_DIR" >> "$LOG_FILE"
    echo "----------------------------------------" >> "$LOG_FILE"
    
    # Display scan information
    echo -e "${CYAN}Scan details:${NC}"
    echo -e "  Directory: ${YELLOW}$SCAN_DIR${NC}"
    echo -e "  Log file: ${YELLOW}$LOG_FILE${NC}"
    echo -e "  Checking files modified in the last ${YELLOW}$DAYS_TO_CHECK${NC} days"
    echo -e "  ClamAV scan: ${YELLOW}$([ "$USE_CLAMAV" -eq 1 ] && echo "Enabled" || echo "Disabled")${NC}"
    echo -e "  Thorough scan: ${YELLOW}$([ "$THOROUGH" -eq 1 ] && echo "Enabled" || echo "Disabled")${NC}"
    echo
    
    # Start time
    start_time=$(date +%s)
    
    # Run all checks
    check_suspicious_php_functions
    check_base64_encoded_content
    check_writable_directories
    check_recent_file_changes
    check_htaccess_files
    check_cron_jobs
    check_unusual_file_permissions
    check_hidden_files
    check_web_shells
    check_iframes_redirects
    check_wp_integrity
    
    # Run ClamAV scan if not disabled
    if [ "$USE_CLAMAV" -eq 1 ]; then
        run_clamav_scan
    fi
    
    # Calculate execution time
    end_time=$(date +%s)
    execution_time=$((end_time - start_time))
    
    # Display summary
    echo
    echo -e "${BLUE}╔════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                   ${GREEN}SCAN SUMMARY REPORT${BLUE}                    ║${NC}"
    echo -e "${BLUE}╚════════════════════════════════════════════════════════════╝${NC}"
    echo
    echo -e "${CYAN}Total files scanned:${NC} ${GREEN}$TOTAL_SCANNED${NC}"
    echo -e "${CYAN}Scan duration:${NC} ${GREEN}$execution_time${NC} seconds"
    echo
    
    if [ ${#BACKDOOR_FILES[@]} -gt 0 ]; then
        echo -e "${RED}Found ${#BACKDOOR_FILES[@]} potential backdoors:${NC}"
        for file in "${BACKDOOR_FILES[@]}"; do
            echo -e "  ${RED}→ $file${NC}"
        done
        echo
    fi
    
    if [ ${#SUSPICIOUS_FILES[@]} -gt 0 ]; then
        echo -e "${YELLOW}Found ${#SUSPICIOUS_FILES[@]} suspicious files:${NC}"
        for file in "${SUSPICIOUS_FILES[@]}"; do
            echo -e "  ${YELLOW}→ $file${NC}"
        done
        echo
    fi
    
    if [ ${#HTACCESS_ISSUES[@]} -gt 0 ]; then
        echo -e "${YELLOW}Found ${#HTACCESS_ISSUES[@]} suspicious .htaccess files:${NC}"
        for file in "${HTACCESS_ISSUES[@]}"; do
            echo -e "  ${YELLOW}→ $file${NC}"
        done
        echo
    fi
    
    if [ ${#CRON_ISSUES[@]} -gt 0 ]; then
        echo -e "${YELLOW}Found ${#CRON_ISSUES[@]} suspicious cron entries:${NC}"
        for entry in "${CRON_ISSUES[@]}"; do
            echo -e "  ${YELLOW}→ $entry${NC}"
        done
        echo
    fi
    
    if [ ${#WRITABLE_DIRS[@]} -gt 0 ]; then
        echo -e "${YELLOW}Found ${#WRITABLE_DIRS[@]} writable directories:${NC}"
        for dir in "${WRITABLE_DIRS[@]}"; do
            echo -e "  ${YELLOW}→ $dir${NC}"
        done
        echo
    fi
    
    # Check if any issues were found
    total_issues=$((${#BACKDOOR_FILES[@]} + ${#SUSPICIOUS_FILES[@]} + ${#HTACCESS_ISSUES[@]} + ${#CRON_ISSUES[@]}))
    
    if [ $total_issues -gt 0 ]; then
        echo -e "${RED}=============================================${NC}"
        echo -e "${RED}WARNING: Potential security issues detected!${NC}"
        echo -e "${RED}=============================================${NC}"
        echo -e "${YELLOW}Please review the log file for details: $LOG_FILE${NC}"
        
        # Suggest next steps
        echo
        echo -e "${CYAN}Recommended next steps:${NC}"
        echo -e "  ${GREEN}1. Analyze the suspicious files to confirm if they are malicious${NC}"
        echo -e "  ${GREEN}2. Remove or quarantine confirmed malicious files${NC}"
        echo -e "  ${GREEN}3. Update all CMS platforms, plugins, and themes${NC}"
        echo -e "  ${GREEN}4. Change all passwords for FTP, database, CMS admin, etc.${NC}"
        echo -e "  ${GREEN}5. Consider implementing a web application firewall${NC}"
        echo -e "  ${GREEN}6. For further cleanup assistance, consider using:${NC}"
        echo -e "     ${CYAN}- https://github.com/gotmls/wordpress-exploit-scanner${NC} (WordPress)"
        echo -e "     ${CYAN}- https://github.com/abantu-php/detector${NC} (PHP)"
        echo -e "     ${CYAN}- https://github.com/nbs-system/php-malware-finder${NC} (Advanced PHP Malware Detection)"
    else
        echo -e "${GREEN}=============================================${NC}"
        echo -e "${GREEN}No obvious security issues detected!${NC}"
        echo -e "${GREEN}=============================================${NC}"
        echo
        echo -e "${CYAN}Recommendations:${NC}"
        echo -e "  ${GREEN}1. Regularly update all software components${NC}"
        echo -e "  ${GREEN}2. Implement proper file permissions${NC}"
        echo -e "  ${GREEN}3. Consider using a web application firewall${NC}"
        echo -e "  ${GREEN}4. Perform regular security scans${NC}"
    fi
    
    echo
    echo -e "${BLUE}Scan completed! Full details saved to: ${YELLOW}$LOG_FILE${NC}"
}

# -----------------------------------------------------------------------------
# Additional Helper Functions
# -----------------------------------------------------------------------------

check_file_changes() {
    log_message "INFO" "Checking for file changes using stored checksums (if available)"
    echo -e "\n${CYAN}Checking for file changes using stored checksums...${NC}"
    
    # Path to store checksums
    checksum_file="$SCAN_DIR/.php_hack_detector_checksums"
    
    # Check if we have previous checksums
    if [ -f "$checksum_file" ]; then
        log_message "INFO" "Previous checksums found, comparing files"
        
        # Create temporary files
        old_checksums=$(mktemp)
        new_checksums=$(mktemp)
        
        # Load previous checksums
        cat "$checksum_file" > "$old_checksums"
        
        # Generate new checksums
        find "$SCAN_DIR" -type f -name "*.php" -o -name "*.phtml" -o -name "*.inc" -o -name ".htaccess" | \
            xargs -I{} md5sum "{}" 2>/dev/null | sort > "$new_checksums"
        
        # Compare checksums
        changed_files=$(diff "$old_checksums" "$new_checksums" | grep "^[<>]" | awk '{print $3}')
        
        if [ -n "$changed_files" ]; then
            log_message "ALERT" "Detected changes in the following files:"
            echo "$changed_files" | while read -r file; do
                log_message "ALERT" "  - $file"
                MODIFIED_FILES+=("$file")
            done
            
            echo -e "${YELLOW}Detected changes in $(echo "$changed_files" | wc -l) files since last scan${NC}"
        else
            log_message "INFO" "No file changes detected since last scan"
            echo -e "${GREEN}No file changes detected since last scan${NC}"
        fi
        
        # Clean up
        rm -f "$old_checksums" "$new_checksums"
        
        # Update checksums if requested
        if [ "$THOROUGH" -eq 1 ]; then
            log_message "INFO" "Updating checksums file"
            find "$SCAN_DIR" -type f -name "*.php" -o -name "*.phtml" -o -name "*.inc" -o -name ".htaccess" | \
                xargs -I{} md5sum "{}" 2>/dev/null | sort > "$checksum_file"
        fi
    else
        log_message "INFO" "No previous checksums found, creating initial checksums file"
        echo -e "${YELLOW}No previous checksums found. Creating initial checksums file for future comparisons.${NC}"
        
        # Create initial checksums file
        find "$SCAN_DIR" -type f -name "*.php" -o -name "*.phtml" -o -name "*.inc" -o -name ".htaccess" | \
            xargs -I{} md5sum "{}" 2>/dev/null | sort > "$checksum_file"
        
        log_message "INFO" "Created initial checksums file: $checksum_file"
    fi
}

check_database_connection() {
    # This function is a placeholder for database scanning 
    # You would need to expand this based on your specific database system
    
    log_message "INFO" "Checking for database access (if available)"
    echo -e "\n${CYAN}Checking for database access...${NC}"
    
    # Check for WordPress config file with database credentials
    if [ -f "$SCAN_DIR/wp-config.php" ]; then
        log_message "INFO" "WordPress config file found, extracting database info"
        
        # Extract database info (this is a simplified approach)
        db_name=$(grep DB_NAME "$SCAN_DIR/wp-config.php" | cut -d "'" -f 4)
        db_user=$(grep DB_USER "$SCAN_DIR/wp-config.php" | cut -d "'" -f 4)
        db_host=$(grep DB_HOST "$SCAN_DIR/wp-config.php" | cut -d "'" -f 4)
        
        if [ -n "$db_name" ] && [ -n "$db_user" ] && [ -n "$db_host" ]; then
            log_message "INFO" "Found database configuration: DB=$db_name, Host=$db_host"
            
            # Check if we have mysql/mariadb client available
            if check_command "mysql"; then
                log_message "INFO" "MySQL client found, you can check the database manually with:"
                log_message "INFO" "  mysql -h $db_host -u $db_user -p $db_name"
                
                echo -e "${YELLOW}Database access information found.${NC}"
                echo -e "${YELLOW}You may want to check for suspicious users or content in the database.${NC}"
                echo -e "${YELLOW}MySQL command: mysql -h $db_host -u $db_user -p $db_name${NC}"
                
                # Suggest some queries to check
                echo -e "${CYAN}Suggested queries to check for WordPress database issues:${NC}"
                echo -e "${GREEN}  SELECT * FROM wp_users WHERE user_registered > DATE_SUB(NOW(), INTERVAL 30 DAY);${NC}"
                echo -e "${GREEN}  SELECT * FROM wp_options WHERE option_name LIKE '%seo%' AND option_value LIKE '%http%';${NC}"
                echo -e "${GREEN}  SELECT * FROM wp_posts WHERE post_content LIKE '%<iframe%' OR post_content LIKE '%eval%';${NC}"
            else
                log_message "INFO" "MySQL client not found, skipping database checks"
                echo -e "${YELLOW}Database configuration found, but MySQL client is not available${NC}"
            fi
        fi
    else
        log_message "INFO" "No database configuration files found, skipping database checks"
        echo -e "${YELLOW}No database configuration files found, skipping database checks${NC}"
    fi
}

# Execute main function if script is being run directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi