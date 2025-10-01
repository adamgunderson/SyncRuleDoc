# FireMon Rule Documentation Sync Script

Automatically syncs FireMon rule documentation (custom properties) from management stations to their child devices.

## Overview

This script solves the problem of keeping rule documentation synchronized between management stations (like Panorama, FMC, etc.) and their managed devices. When you document rules on a management station, this script propagates those custom properties to the corresponding rules on all child devices.

## Features

- Automatically discovers all management stations in a domain
- Matches rules between management stations and child devices based on rule definitions
- Syncs custom property values from management station rules to child device rules
- Supports all custom property types (STRING, INTEGER, DATE, BOOLEAN, etc.)
- Handles authentication with token refresh
- Provides detailed logging and progress tracking
- Can sync all management stations or target a specific one

## Requirements

- Python 3.6+
- FireMon Security Manager
- Access to FireMon API with appropriate permissions
- Required Python packages (automatically available on FireMon server):
  - `requests`
  - `urllib3`

## Installation

1. Clone or download this script to your FireMon server or workstation
2. Ensure you have network access to your FireMon Security Manager

## Configuration

The script uses environment variables for configuration:

```bash
# Required
export FIREMON_URL="https://your-firemon-server.com"
export FIREMON_USER="your-username"
export FIREMON_PASSWORD='your-password'

# Optional
export FIREMON_DOMAIN_ID="1"                    # Default: 1
export FIREMON_PAGE_SIZE="100"                  # Default: 100
export FIREMON_LOG_FILE="./sync_ruledoc.log"    # Default: ./sync_ruledoc.log
export FIREMON_LOG_LEVEL="INFO"                 # Default: INFO (options: DEBUG, INFO, WARNING, ERROR)
export FIREMON_LOG_MAX_BYTES="10485760"         # Default: 10MB (log rotation size)
export FIREMON_LOG_BACKUP_COUNT="5"             # Default: 5 (number of rotated logs to keep)
export FIREMON_VERIFY_SSL="false"               # Default: false
```

## Usage

### Test Connection

Before running a sync, test your connection:

```bash
python3.12 sync_ruledoc.py --test
```

### Sync All Management Stations

Sync all management stations in the domain:

```bash
python3.12 sync_ruledoc.py
```

### Sync Specific Management Station

Sync only a specific management station by ID:

```bash
python3.12 sync_ruledoc.py --mgmt-id 1289
```

### Enable Debug Logging

Get detailed logging output:

```bash
python3.12 sync_ruledoc.py --debug
```

### Running as a Cron Job

To automatically sync rule documentation on a schedule, set up a cron job:

1. **Edit the crontab**:
   ```bash
   crontab -e
   ```

2. **Add a cron entry**. Examples:

   **Run every day at 2:00 AM:**
   ```cron
   0 2 * * * cd /path/to/script && /usr/bin/python3.12 /path/to/script/sync_ruledoc.py >> /var/log/sync_ruledoc_cron.log 2>&1
   ```

   **Run every 6 hours:**
   ```cron
   0 */6 * * * cd /path/to/script && /usr/bin/python3.12 /path/to/script/sync_ruledoc.py >> /var/log/sync_ruledoc_cron.log 2>&1
   ```

   **Run every Monday at 3:00 AM:**
   ```cron
   0 3 * * 1 cd /path/to/script && /usr/bin/python3.12 /path/to/script/sync_ruledoc.py >> /var/log/sync_ruledoc_cron.log 2>&1
   ```

3. **Environment variables in cron**: Since cron jobs don't inherit your environment, you have two options:

   **Option A: Use a wrapper script**

   Create `/path/to/script/sync_ruledoc_wrapper.sh`:
   ```bash
   #!/bin/bash
   export FIREMON_URL="https://your-firemon-server.com"
   export FIREMON_USER="your-username"
   export FIREMON_PASSWORD='your-password'
   export FIREMON_DOMAIN_ID="1"
   export FIREMON_LOG_FILE="/var/log/firemon/sync_ruledoc.log"

   cd /path/to/script
   /usr/bin/python3.12 /path/to/script/sync_ruledoc.py
   ```

   Make it executable:
   ```bash
   chmod +x /path/to/script/sync_ruledoc_wrapper.sh
   ```

   Cron entry:
   ```cron
   0 2 * * * /path/to/script/sync_ruledoc_wrapper.sh >> /var/log/sync_ruledoc_cron.log 2>&1
   ```

   **Option B: Set environment variables in crontab**
   ```cron
   FIREMON_URL=https://your-firemon-server.com
   FIREMON_USER=your-username
   FIREMON_PASSWORD=your-password
   FIREMON_DOMAIN_ID=1
   FIREMON_LOG_FILE=/var/log/firemon/sync_ruledoc.log

   0 2 * * * cd /path/to/script && /usr/bin/python3.12 /path/to/script/sync_ruledoc.py >> /var/log/sync_ruledoc_cron.log 2>&1
   ```

4. **Verify cron job is running**:
   ```bash
   # List current cron jobs
   crontab -l

   # Check cron logs
   grep CRON /var/log/cron

   # Check script output
   tail -f /var/log/sync_ruledoc_cron.log
   ```

## How It Works

1. **Discovery**: Queries FireMon for all management stations (or a specific one)
2. **Rule Retrieval**: Fetches all rules with custom properties from each management station
3. **Child Device Discovery**: Finds all devices managed by each management station
4. **Rule Matching**: Matches management station rules to child device rules based on:
   - Rule name
   - Policy name
   - Action
   - Sources, destinations, services
   - Zones and direction
5. **Property Sync**: Updates matched child device rules with management station custom properties
6. **Reporting**: Provides summary statistics on sync results

## Rule Matching Logic

Rules are matched between management stations and child devices when they have identical:

- Rule name
- Policy name
- Rule action (ALLOW, DENY, etc.)
- Direction (INBOUND, OUTBOUND, etc.)
- Source network objects
- Destination network objects
- Service objects
- Source zones
- Destination zones

This ensures that only truly corresponding rules have their documentation synchronized.

## Output

The script provides:

- Console output with progress and status messages
- Detailed log file with automatic rotation (default: `sync_ruledoc.log`)
  - Rotates when log reaches 10MB (configurable)
  - Keeps 5 backup logs (configurable)
  - Log files: `sync_ruledoc.log`, `sync_ruledoc.log.1`, `sync_ruledoc.log.2`, etc.
- Summary statistics including:
  - Management stations processed
  - Child devices processed
  - Rules matched
  - Rules updated
  - Rules failed
  - Rules with no match

### Example Output

```
================================================================================
Sync Summary:
================================================================================
Management stations processed: 3
Child devices processed: 12
Rules matched: 245
Rules updated: 187
Rules failed: 0
Rules with no match: 58
================================================================================
```

## Exit Codes

- `0`: Success (no failures)
- `1`: Error occurred (authentication failure, API error, or rule update failures)

## Logging

Logs are written to both console and a log file. Log levels:

- **INFO**: Normal operation messages
- **WARNING**: Non-critical issues (e.g., no rules found on a device)
- **ERROR**: Critical errors that prevent sync
- **DEBUG**: Detailed information for troubleshooting

## Troubleshooting

### Authentication Failures

```bash
# Verify credentials
python3.12 sync_ruledoc.py --test

# Check environment variables
echo $FIREMON_URL
echo $FIREMON_USER
```

### No Rules Found

- Ensure rules exist on the management station
- Verify rules have custom properties set
- Check that child devices are properly associated with management station

### Rule Update Failures

- Enable debug logging: `--debug`
- Check API permissions for your user account
- Verify rule IDs are valid
- Review log file for specific error messages

### 400 Bad Request Errors

- Ensure custom property definitions exist in FireMon
- Verify property types match (STRING, INTEGER, etc.)
- Check that rule IDs are valid

## Limitations

- Only syncs rules that already exist on child devices (doesn't create new rules)
- Requires exact rule matching based on rule definition
- Custom properties must be defined in FireMon before syncing
- Only processes rules with existing custom properties on management station

## Security Considerations

- Store credentials in environment variables, not in code
- Use HTTPS for API connections
- Limit API user permissions to minimum required
- Protect log files as they may contain sensitive information
- Consider using service accounts with appropriate RBAC

## Related Scripts

- `import_ruledoc.py`: Import rule documentation from CSV files

## Support

For issues or questions:

1. Check the log file for detailed error messages
2. Run with `--debug` flag for verbose output
3. Verify API connectivity with `--test` option
4. Review FireMon API documentation

## Version History

- **1.0**: Initial release with core sync functionality
- Support for all custom property types
- Automatic rule matching between management stations and child devices
- Progress tracking and detailed logging

## License

**Use at your own risk. No warranty provided.**

This script is provided "as is" without warranty of any kind, either express or implied, including but not limited to the implied warranties of merchantability and fitness for a particular purpose. The author assumes no responsibility for errors or omissions in this script or documentation.

In no event shall the author be liable for any special, direct, indirect, consequential, or incidental damages or any damages whatsoever, whether in an action of contract, negligence or other tort, arising out of or in connection with the use of this script or the performance of this script.

**By using this script, you acknowledge that:**
- You have tested it thoroughly in a non-production environment
- You understand the changes it will make to your FireMon configuration
- You accept full responsibility for any outcomes resulting from its use
- You will maintain appropriate backups before running the script
