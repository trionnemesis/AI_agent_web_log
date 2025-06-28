from __future__ import annotations
"""日誌解析與啟發式評分輔助函式"""

import re
import urllib.parse
from typing import List, Dict, Tuple

# 改善：使用正則表達式模式，支援更靈活的匹配
SUSPICIOUS_PATTERNS = [
    # 路徑遍歷攻擊
    r'(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e%5c)',
    # SQL 注入模式（支援大小寫變形和編碼）
    r'(?i)(?:union|select|insert|update|delete|drop|create)\s+',
    # XSS 攻擊
    r'(?i)<script[^>]*>|javascript:|vbscript:|on\w+\s*=',
    # 命令注入
    r'(?i)(?:cmd|exec|system|eval|shell)',
    # 檔案包含
    r'(?i)(?:/etc/passwd|/etc/shadow|/proc/|/sys/)',
    # 編碼變形檢測
    r'(?i)(?:%20|%2b|%2d|%2e|%2f|%3c|%3e|%3d|%3f|%40)',
]

# 改善：動態權重配置，基於攻擊嚴重性
PATTERN_WEIGHTS = {
    'path_traversal': 0.3,
    'sql_injection': 0.4,
    'xss': 0.35,
    'command_injection': 0.45,
    'file_inclusion': 0.3,
    'encoding_evasion': 0.2,
}

# 改善：更完整的掃描器特徵
SCANNER_SIGNATURES = {
    'nmap': 0.25,
    'sqlmap': 0.4,
    'nikto': 0.3,
    'curl/': 0.15,
    'python-requests': 0.1,
    'wget': 0.1,
    'masscan': 0.35,
    'dirb': 0.2,
    'gobuster': 0.2,
}

# 改善：狀態碼嚴重性分級
STATUS_SEVERITY = {
    'client_error': 0.2,    # 4xx
    'server_error': 0.3,    # 5xx
    'redirect': 0.1,        # 3xx
    'success': 0.0,         # 2xx
}


def parse_status(line: str) -> int:
    """從 Apache/Nginx 等格式的日誌行擷取 HTTP 狀態碼"""

    try:
        parts = line.split("\"")
        if len(parts) > 2:
            status_part = parts[2].strip().split()[0]
            return int(status_part)
    except Exception:
        pass
    return 0


def response_time(line: str) -> float:
    """讀取行內的回應時間數值，若無則回傳 0"""

    if "resp_time:" in line:
        try:
            val_str = line.split("resp_time:")[1].split()[0].split("\"")[0]
            return float(val_str)
        except (ValueError, IndexError):
            pass
    return 0.0


def decode_url_components(line: str) -> str:
    """解碼 URL 編碼的組件，防止編碼繞過"""
    try:
        # 提取 URL 部分並解碼
        url_match = re.search(r'GET\s+([^\s]+)|POST\s+([^\s]+)', line)
        if url_match:
            url = url_match.group(1) or url_match.group(2)
            decoded = urllib.parse.unquote(url)
            return line.replace(url, decoded)
    except Exception:
        pass
    return line


def detect_pattern_matches(line: str) -> List[Tuple[str, float]]:
    """使用正則表達式檢測攻擊模式，回傳匹配的模式和權重"""
    matches = []
    decoded_line = decode_url_components(line)
    
    for i, pattern in enumerate(SUSPICIOUS_PATTERNS):
        if re.search(pattern, decoded_line, re.IGNORECASE):
            # 根據模式類型分配權重
            if i < 1:  # 路徑遍歷
                weight = PATTERN_WEIGHTS['path_traversal']
            elif i < 2:  # SQL 注入
                weight = PATTERN_WEIGHTS['sql_injection']
            elif i < 3:  # XSS
                weight = PATTERN_WEIGHTS['xss']
            elif i < 4:  # 命令注入
                weight = PATTERN_WEIGHTS['command_injection']
            elif i < 5:  # 檔案包含
                weight = PATTERN_WEIGHTS['file_inclusion']
            else:  # 編碼變形
                weight = PATTERN_WEIGHTS['encoding_evasion']
            matches.append((pattern, weight))
    
    return matches


def calculate_status_score(status: int) -> float:
    """根據狀態碼計算分數，考慮嚴重性分級"""
    if 200 <= status < 300:
        return STATUS_SEVERITY['success']
    elif 300 <= status < 400:
        return STATUS_SEVERITY['redirect']
    elif 400 <= status < 500:
        return STATUS_SEVERITY['client_error']
    elif 500 <= status < 600:
        return STATUS_SEVERITY['server_error']
    return 0.0


def detect_scanner_signature(line: str) -> float:
    """檢測掃描器特徵，回傳加權分數"""
    line_lower = line.lower()
    max_score = 0.0
    
    for signature, weight in SCANNER_SIGNATURES.items():
        if signature.lower() in line_lower:
            max_score = max(max_score, weight)
    
    return max_score


def fast_score(line: str) -> float:
    """改善的啟發式評分函式，具備更強的攻擊檢測能力
    
    改善重點：
    1. 使用正則表達式支援更靈活的模式匹配
    2. 動態權重配置，基於攻擊嚴重性
    3. URL 解碼防止編碼繞過
    4. 更完整的掃描器特徵庫
    5. 狀態碼嚴重性分級
    """
    
    score = 0.0
    
    # 1. 狀態碼分析（改善：分級權重）
    status = parse_status(line)
    score += calculate_status_score(status)
    
    # 2. 回應時間分析（保持原有邏輯）
    resp_time = response_time(line)
    if resp_time > 1.0:
        score += 0.2
    
    # 3. 攻擊模式檢測（改善：正則表達式 + 動態權重）
    pattern_matches = detect_pattern_matches(line)
    for pattern, weight in pattern_matches:
        score += weight
    
    # 4. 掃描器特徵檢測（改善：更完整的特徵庫 + 動態權重）
    scanner_score = detect_scanner_signature(line)
    score += scanner_score
    
    # 5. 額外啟發式規則
    # 檢測異常的請求頻率指標（如果有多個相同 IP 的請求）
    if line.count('"') > 6:  # 異常的引號數量可能表示注入
        score += 0.1
    
    # 檢測異常的請求長度
    if len(line) > 1000:  # 過長的請求可能包含大量注入內容
        score += 0.15
    
    # 檢測編碼密度
    encoded_chars = len(re.findall(r'%[0-9a-fA-F]{2}', line))
    if encoded_chars > 5:  # 高編碼密度可能表示繞過嘗試
        score += 0.1
    
    return min(score, 1.0)
