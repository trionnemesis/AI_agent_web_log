#!/usr/bin/env python3
"""
LMS Log Analyzer 模組入口點

這個檔案允許使用 python -m lms_log_analyzer 執行程式
使用方式：
    python -m lms_log_analyzer --mode file
    python -m lms_log_analyzer --mode opensearch --continuous
    python -m lms_log_analyzer --stats
"""

from .main import main

if __name__ == "__main__":
    main()