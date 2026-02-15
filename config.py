import os

class Config:
    BASE_URL = "https://forcedcinema.net"
    VIDEOS_PER_PAGE = 10
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-key-for-education-only'