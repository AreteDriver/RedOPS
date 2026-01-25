#!/bin/bash
# RedOPS Notification Script
# Called after scheduled scans complete

set -euo pipefail

# Get the latest scan result
LATEST_REPORT=$(ls -t /var/lib/redops/output/executive_summary_*.md 2>/dev/null | head -1)

if [[ -z "$LATEST_REPORT" ]]; then
    echo "No report found to notify about"
    exit 0
fi

# Extract summary from report
SUMMARY=$(head -50 "$LATEST_REPORT" | grep -A5 "## Summary" || echo "Scan completed")

# Slack notification
if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
    curl -s -X POST "$SLACK_WEBHOOK_URL" \
        -H 'Content-Type: application/json' \
        -d @- <<EOF
{
    "text": "RedOPS Security Scan Complete",
    "blocks": [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": "RedOPS Security Scan Complete"
            }
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "Target: *${REDOPS_TARGET:-unknown}*\nPreset: *${REDOPS_PRESET:-quick}*\nReport: \`$(basename "$LATEST_REPORT")\`"
            }
        }
    ]
}
EOF
    echo "Slack notification sent"
fi

# Discord notification
if [[ -n "${DISCORD_WEBHOOK_URL:-}" ]]; then
    curl -s -X POST "$DISCORD_WEBHOOK_URL" \
        -H 'Content-Type: application/json' \
        -d @- <<EOF
{
    "embeds": [{
        "title": "RedOPS Security Scan Complete",
        "color": 5814783,
        "fields": [
            {"name": "Target", "value": "${REDOPS_TARGET:-unknown}", "inline": true},
            {"name": "Preset", "value": "${REDOPS_PRESET:-quick}", "inline": true},
            {"name": "Report", "value": "$(basename "$LATEST_REPORT")"}
        ]
    }]
}
EOF
    echo "Discord notification sent"
fi

# Email notification
if [[ -n "${NOTIFY_EMAIL:-}" && -n "${SMTP_HOST:-}" ]]; then
    echo "Email notifications require mailx or sendmail - skipping"
fi

echo "Notifications complete"
