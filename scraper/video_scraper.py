import requests
from bs4 import BeautifulSoup
from config import Config
import re


class VideoScraper:
    def __init__(self):
        self.base_url = Config.BASE_URL
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': Config.USER_AGENT,
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive'
        })

    def scrape_video(self, video_slug):
        """Scrape individual video page data"""
        url = f"{self.base_url}/video/{video_slug}/"

        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'lxml')

            video_data = {
                'title': self.extract_title(soup),
                'views': self.extract_views(soup),
                'rating': self.extract_rating(soup),
                'likes': self.extract_likes(soup),
                'dislikes': self.extract_dislikes(soup),
                'date': self.extract_date(soup),
                'stars': self.extract_stars(soup),
                'movie': self.extract_movie(soup),
                'categories': self.extract_categories(soup),
                'tags': self.extract_tags(soup),
                'description': self.extract_description(soup),
                'video_url': self.construct_video_url(video_slug),
                'preview_image': self.extract_og_image(soup)
            }

            return video_data

        except requests.RequestException as e:
            print(f"[ERROR] Scraping video {video_slug}: {e}")
            return {
                'title': '',
                'views': '0',
                'rating': '0',
                'likes': '0',
                'dislikes': '0',
                'date': '',
                'stars': {'name': 'Unknown', 'url': ''},
                'movie': {'title': 'Unknown', 'url': ''},
                'categories': [],
                'tags': [],
                'description': '',
                'video_url': '',
                'preview_image': ''
            }

    # ===============================
    # BASIC EXTRACTIONS
    # ===============================

    def extract_title(self, soup):
        title_tag = soup.find('h1', class_='entry-title')
        return title_tag.get_text(strip=True) if title_tag else ''

    def extract_views(self, soup):
        views_div = soup.find('div', id='video-views')
        if views_div:
            views_text = views_div.get_text(strip=True)
            match = re.search(r'([\d.]+[KM]?)', views_text)
            return match.group(1) if match else '0'
        return '0'

    def extract_rating(self, soup):
        meter = soup.find('div', class_='rating-bar-meter')
        if meter and meter.get('style'):
            style = meter['style']
            return (
                style.replace('width:', '')
                     .replace('%', '')
                     .replace(';', '')
                     .strip()
            )
        return '0'

    def extract_likes(self, soup):
        likes_span = soup.find('span', class_='likes_count')
        return likes_span.get_text(strip=True) if likes_span else '0'

    def extract_dislikes(self, soup):
        dislikes_span = soup.find('span', class_='dislikes_count')
        return dislikes_span.get_text(strip=True) if dislikes_span else '0'

    def extract_date(self, soup):
        date_div = soup.find('div', id='video-date')
        if date_div:
            date_text = date_div.get_text(strip=True)
            return date_text.replace('Date:', '').strip()
        return ''

    # ===============================
    # STARS & MOVIE
    # ===============================

    def extract_stars(self, soup):
        stars_div = soup.find('div', id='video-stars')
        if stars_div:
            stars_link = stars_div.find('a')
            if stars_link:
                return {
                    'name': stars_link.get_text(strip=True),
                    'url': stars_link.get('href', '')
                }
        return {'name': 'Unknown', 'url': ''}

    def extract_movie(self, soup):
        movie_div = soup.find('div', id='video-movies')
        if movie_div:
            movie_link = movie_div.find('a')
            if movie_link:
                return {
                    'title': movie_link.get_text(strip=True),
                    'url': movie_link.get('href', '')
                }
        return {'title': 'Unknown', 'url': ''}

    # ===============================
    # TAGS & CATEGORIES
    # ===============================

    def extract_categories(self, soup):
        categories = []
        category_links = soup.select('.tags-list a[href*="/category/"]')
        for link in category_links:
            categories.append({
                'name': link.get_text(strip=True),
                'url': link.get('href', '')
            })
        return categories

    def extract_tags(self, soup):
        tags = []
        tag_links = soup.select('.tags-list a[href*="/tag/"]')
        for link in tag_links:
            tags.append({
                'name': link.get_text(strip=True),
                'url': link.get('href', '')
            })
        return tags

    # ===============================
    # DESCRIPTION
    # ===============================

    def extract_description(self, soup):
        desc_div = soup.find('div', class_='video-description')
        if desc_div:
            desc_content = desc_div.find('div', class_='desc')
            return desc_content.get_text(strip=True) if desc_content else ''
        return ''

    # ===============================
    # OG IMAGE (PREVIEW IMAGE)
    # ===============================

    def extract_og_image(self, soup):
        og_image = soup.find('meta', property='og:image')
        
        if og_image and og_image.get('content'):
            return og_image['content']
        return ''

    # ===============================
    # VIDEO FILE URL
    # ===============================

    def construct_video_url(self, video_slug):
        return f"https://vod.forcedcinema.net/{video_slug}.mp4"
