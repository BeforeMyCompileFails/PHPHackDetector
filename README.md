# 🛡️ PHP Hack Detector

A Bash script for scanning PHP-based websites for common web-based threats including backdoors, injections, malicious cron jobs, suspicious file permissions, and more.

---

## Features

- ✅ Detects obfuscated and dangerous PHP functions
- 🔐 Finds backdoors, web shells, and base64-encoded payloads
- 🧪 Integrates with ClamAV (optional)
- 📁 Identifies writable directories with PHP files
- 🕵️ Checks `.htaccess` for malicious modifications
- 🕒 Detects recently modified and hidden files
- 🧩 WordPress-specific core integrity & user checks
- 📝 Generates detailed logs and summary report
- 💾 File checksum support for change tracking
- ⚙️ Verbose and thorough scanning modes

---

## Installation

Clone the repository and make the script executable:

```bash
git clone https://github.com/BeforeMyCompileFails/php-hack-detector.git
cd php-hack-detector
chmod +x php-hack-detector.sh
```

---

## Usage

```bash
./php-hack-detector.sh [options]
```

### Options:

| Flag                  | Description                                            |
|-----------------------|--------------------------------------------------------|
| `-d`, `--directory`   | Directory to scan (default: current directory)         |
| `-l`, `--log`         | Log file name (default: auto-generated)                |
| `-t`, `--days`        | Modified files to check in last N days (default: 7)    |
| `-n`, `--no-clamav`   | Disable ClamAV virus scan                              |
| `-v`, `--verbose`     | Enable verbose logging                                 |
| `-T`, `--thorough`    | Enable thorough (slower) scan and checksum updates     |
| `-h`, `--help`        | Show help and usage                                    |

---

## Example

```bash
sudo ./php-hack-detector.sh -d /var/www/html -v -T
```

---

## Requirements

- Bash (tested on Bash 4+)
- Optional: `clamscan` (for virus scanning)
- Optional: `wp-cli` (for advanced WordPress checks)

---

## Recommendations After Scan

If issues are found:

1. Review logs and flagged files
2. Remove/quarantine confirmed malware
3. Reset all passwords (FTP, CMS, DB, etc.)
4. Update CMS, plugins, and server software
5. Consider deploying a Web Application Firewall (WAF)

---

## License

MIT

---

## Credits

Inspired by community PHP security tools:
- [PHP Malware Finder](https://github.com/nbs-system/php-malware-finder)
- [WordPress Exploit Scanner](https://github.com/gotmls/wordpress-exploit-scanner)

---

## Contributing

Pull requests and feedback welcome!
