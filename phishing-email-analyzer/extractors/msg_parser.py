"""MSG file parser for Outlook emails.

This module provides functionality to parse .msg files (Outlook Message Format)
and extract email content for analysis.
"""

import os
import re
from typing import Optional, Dict, Any
from dataclasses import dataclass, field


@dataclass
class MSGContent:
    """Parsed MSG file content."""

    subject: str = ""
    sender: str = ""
    sender_email: str = ""
    to: str = ""
    cc: str = ""
    date: str = ""
    body: str = ""
    html_body: str = ""
    headers: Dict[str, str] = field(default_factory=dict)
    attachments: list = field(default_factory=list)
    raw_content: str = ""


def try_install_msg_parser() -> bool:
    """Try to install msg-parser package.

    Returns:
        True if successful or already installed
    """
    try:
        import subprocess
        result = subprocess.run(
            ['pip', 'install', 'msg-parser', '-q'],
            capture_output=True,
            timeout=60
        )
        return result.returncode == 0
    except Exception:
        return False


def parse_msg_with_python(text_content: str) -> MSGContent:
    """Parse MSG content from text representation.

    When msg-parser is not available, this provides basic fallback.

    Args:
        text_content: Text content extracted from MSG

    Returns:
        MSGContent object
    """
    content = MSGContent()
    content.raw_content = text_content

    lines = text_content.split('\n')
    body_start = 0

    for i, line in enumerate(lines):
        if line.startswith('Subject:'):
            content.subject = line[8:].strip()
            body_start = i + 1
        elif line.startswith('From:'):
            content.sender = line[5:].strip()
            email_match = re.search(r'<(.+?)>', line)
            if email_match:
                content.sender_email = email_match.group(1)
        elif line.startswith('To:'):
            content.to = line[3:].strip()
        elif line.startswith('Cc:'):
            content.cc = line[3:].strip()
        elif line.startswith('Date:'):
            content.date = line[5:].strip()

        if line.strip() == '' and i > 10:
            body_start = i + 1
            break

    content.body = '\n'.join(lines[body_start:]).strip()

    return content


def extract_msg_as_text(msg_file_path: str) -> str:
    """Extract MSG file as text using multiple methods.

    This function tries different approaches to extract text from .msg files.

    Args:
        msg_file_path: Path to .msg file

    Returns:
        Text representation of the email

    Raises:
        FileNotFoundError: If file doesn't exist
        ValueError: If no parser is available
    """
    if not os.path.exists(msg_file_path):
        raise FileNotFoundError(f"File not found: {msg_file_path}")

    try:
        import extract_msg

        msg = extract_msg.Message(msg_file_path)

        parts = []

        if msg.subject:
            parts.append(f"Subject: {msg.subject}")

        if msg.sender:
            parts.append(f"From: {msg.sender}")
            if hasattr(msg, 'sender_email') and msg.sender_email:
                parts.append(f"From: {msg.sender} <{msg.sender_email}>")

        if msg.to:
            parts.append(f"To: {msg.to}")

        if msg.cc:
            parts.append(f"Cc: {msg.cc}")

        if msg.date:
            parts.append(f"Date: {msg.date}")

        if hasattr(msg, 'header') and msg.header:
            parts.append("")
            parts.append("--- Headers ---")
            parts.append(str(msg.header))

        if msg.body:
            parts.append("")
            parts.append("--- Body ---")
            parts.append(msg.body)

        if hasattr(msg, 'htmlBody') and msg.htmlBody:
            parts.append("")
            parts.append("--- HTML Body ---")
            parts.append(msg.htmlBody)

        return '\n'.join(parts)

    except ImportError:
        try:
            import msg_parser

            parser = msg_parser.MsgParser(msg_file_path)
            msg_dict = parser.parse()

            parts = []

            if 'subject' in msg_dict:
                parts.append(f"Subject: {msg_dict['subject']}")

            if 'sender' in msg_dict:
                sender = msg_dict['sender']
                parts.append(f"From: {sender}")

            if 'to' in msg_dict:
                parts.append(f"To: {msg_dict['to']}")

            if 'cc' in msg_dict:
                parts.append(f"Cc: {msg_dict['cc']}")

            if 'date' in msg_dict:
                parts.append(f"Date: {msg_dict['date']}")

            if 'body' in msg_dict:
                parts.append("")
                parts.append("--- Body ---")
                parts.append(msg_dict['body'])

            return '\n'.join(parts)

        except ImportError:
            pass

    return f"[MSG File: {msg_file_path}]\n\nThis is a binary Outlook message file. Install 'extract-msg' or 'msg-parser' for full support.\n\npip install extract-msg\n\nOr use: python -c \"import extract_msg; print(extract_msg.Message('{os.path.basename(msg_file_path)}').body)\""


def is_msg_file(file_path: str) -> bool:
    """Check if file is a MSG file.

    Args:
        file_path: Path to check

    Returns:
        True if file appears to be MSG format
    """
    if not file_path:
        return False

    lower_path = file_path.lower()
    if lower_path.endswith('.msg'):
        return True

    if os.path.exists(file_path):
        try:
            with open(file_path, 'rb') as f:
                header = f.read(8)
                return b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1' in header
        except Exception:
            pass

    return False


def get_msg_info(msg_file_path: str) -> Dict[str, Any]:
    """Get basic info from MSG file without full parsing.

    Args:
        msg_file_path: Path to MSG file

    Returns:
        Dictionary with basic info
    """
    info = {
        'file': os.path.basename(msg_file_path),
        'size': os.path.getsize(msg_file_path),
        'is_msg': is_msg_file(msg_file_path),
        'parser_available': False
    }

    try:
        import extract_msg
        info['parser_available'] = True
    except ImportError:
        try:
            import msg_parser
            info['parser_available'] = True
        except ImportError:
            pass

    return info