import re

def parse_views(views_text):
    """Parse view count from text like '29K' to integer"""
    if not views_text:
        return 0
    
    # Remove non-numeric characters except K, M
    match = re.search(r'([\d.]+)([KM]?)', views_text)
    if not match:
        return 0
    
    number = float(match.group(1))
    suffix = match.group(2)
    
    if suffix == 'K':
        return int(number * 1000)
    elif suffix == 'M':
        return int(number * 1000000)
    else:
        return int(number)

def parse_duration(duration_text):
    """Parse duration from text like '01:52' to seconds or return as is"""
    if not duration_text:
        return ''
    
    # Remove icon text if present
    duration_text = re.sub(r'[^\d:]', '', duration_text)
    
    # Check if it's in MM:SS format
    parts = duration_text.split(':')
    if len(parts) == 2:
        minutes, seconds = parts
        try:
            total_seconds = int(minutes) * 60 + int(seconds)
            return total_seconds
        except ValueError:
            return duration_text
    elif len(parts) == 3:
        hours, minutes, seconds = parts
        try:
            total_seconds = int(hours) * 3600 + int(minutes) * 60 + int(seconds)
            return total_seconds
        except ValueError:
            return duration_text
    
    return duration_text

def format_duration(seconds):
    """Format seconds back to MM:SS or HH:MM:SS"""
    if not isinstance(seconds, (int, float)):
        return seconds
    
    hours = seconds // 3600
    minutes = (seconds % 3600) // 60
    seconds = seconds % 60
    
    if hours > 0:
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    else:
        return f"{minutes:02d}:{seconds:02d}"