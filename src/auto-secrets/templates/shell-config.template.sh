#!/bin/bash
# Auto Secrets Manager
if [[ -f "{{FEATURE_DIR}}/init.sh" ]]; then
  # shellcheck source=/dev/null
  source "{{FEATURE_DIR}}/init.sh"
fi
