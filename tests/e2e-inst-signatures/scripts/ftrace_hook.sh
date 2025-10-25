#!/bin/bash

# Execution script for FTRACE_HOOK test  
# This script triggers commit_creds function calls
# Module management is handled in the setup phase

# Create a simple program that will trigger commit_creds
# We can do this by changing user credentials (like su or sudo operations)
# or by creating processes that change their credentials

# Simple approach: use su to trigger commit_creds
echo "root" | su -c "true" 2>/dev/null || true

# Alternative: create a temporary user and switch to it (more reliable)
# But for simplicity, just trigger some credential operations
id > /dev/null

# Give a moment for the event to be processed  
sleep 1
