import requests
from bs4 import BeautifulSoup
from config import Config
from utils.helpers import parse_duration, parse_views
from concurrent.futures import ThreadPoolExecutor, as_completed


class PageScraper:
    def __init__(self):
        self.base_url = Config.BASE_URL
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': Config.USER_AGENT,
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive'
        })

    def scrape_page(self, page_num=1, custom_path=None):

        if custom_path:
            if page_num > 1:
                url = f"{self.base_url}/{custom_path}/page/{page_num}/"
            else:
                url = f"{self.base_url}/{custom_path}/"
        else:
            url = f"{self.base_url}/page/{page_num}/" if page_num > 1 else f"{self.base_url}/"



        try:
            response = self.session.get(url, timeout=10)
            response.raise_for_status()

            soup = BeautifulSoup(response.text, 'lxml')
            articles = soup.find_all('article', class_='loop-video')

            videos = []

            # ===== MULTITHREADING START =====
            with ThreadPoolExecutor(max_workers=8) as executor:
                futures = [executor.submit(self.extract_card_data, article) for article in articles]

                for future in as_completed(futures):
                    result = future.result()
                    if result:
                        videos.append(result)

            return videos

        except requests.RequestException as e:
            print(f"[ERROR] Scraping page {page_num}: {e}")
            return []

    def extract_card_data(self, article):
        """Extract data from individual video card"""
        try:
            # ================= VIDEO LINK =================
            link_tag = article.find('a', href=True)
            if not link_tag:
                return None

            video_url = link_tag['href'].strip()
            video_slug = video_url.rstrip('/').split('/')[-1]

            # ================= THUMBNAIL =================
            thumbnail = article.find('img')
            thumb_url = ''

            if thumbnail:
                thumb_url = (
                    thumbnail.get('data-src') or
                    thumbnail.get('data-lazy-src') or
                    thumbnail.get('src') or
                    ''
                )

            # ================= TITLE =================
            title = ''
            title_tag = article.find('header', class_='entry-header')

            if title_tag:
                span = title_tag.find('span')
                title = span.get_text(strip=True) if span else title_tag.get_text(strip=True)

            # ================= VIEWS =================
            views = 0
            views_tag = article.find('span', class_='views')
            if views_tag:
                views = parse_views(views_tag.get_text(strip=True))

            # ================= DURATION =================
            duration = ''
            duration_tag = article.find('span', class_='duration')
            if duration_tag:
                duration = parse_duration(duration_tag.get_text(strip=True))

            # ================= RATING =================
            rating = 0
            meter = article.find('div', class_='rating-bar-meter')
            if meter and meter.get('style'):
                style = meter['style']
                rating = (
                    style.replace('width:', '')
                         .replace('%', '')
                         .replace(';', '')
                         .strip()
                )

            # ================= HD STATUS =================
            is_hd = bool(article.find('span', class_='hd-video'))

            # ================= DATA ATTRIBUTES =================
            video_uid = article.get('data-video-uid', '')
            post_id = article.get('data-post-id', '')

            # ================= CLEAN TAGS =================
            classes = article.get('class', [])
            tags = []

            for c in classes:
                if c.startswith('tag-'):
                    tags.append(c.replace('tag-', '').replace('-', ' '))
                elif c.startswith('category-'):
                    tags.append(c.replace('category-', '').replace('-', ' '))
                elif c.startswith('stars-'):
                    tags.append(c.replace('stars-', '').replace('-', ' '))
                elif c.startswith('movies-'):
                    tags.append(c.replace('movies-', '').replace('-', ' '))

            return {
                'id': post_id,
                'uid': video_uid,
                'title': title,
                'url': video_url,
                'slug': video_slug,
                'thumbnail': thumb_url,
                'views': views,
                'duration': duration,
                'rating': rating,
                'is_hd': is_hd,
                'tags': tags
            }

        except Exception as e:
            print(f"[ERROR] Extracting card data: {e}")
            return None
