from flask import Flask, render_template, request, jsonify, redirect, url_for
from scraper.page_scraper import PageScraper
from scraper.video_scraper import VideoScraper
from config import Config
import logging
import time

app = Flask(__name__)
app.config.from_object(Config)

# Setup logging
logging.basicConfig(level=logging.INFO)


# ===============================
# Helper: Retry Wrapper
# ===============================
def retry_scrape(scrape_function, *args, retries=3, delay=1):
    """
    Retry wrapper for scraper functions
    """
    for attempt in range(1, retries + 1):
        try:
            result = scrape_function(*args)
            if result:  # If valid data returned
                return result
            logging.warning(f"Attempt {attempt}: No data returned.")
        except Exception as e:
            logging.error(f"Attempt {attempt} failed: {e}")

        if attempt < retries:
            time.sleep(delay)

    return None


# ===============================
# HOME PAGE
# ===============================
@app.route('/')
@app.route('/page/<int:page_num>')
def index(page_num=1):
    """Home page displaying video cards with retry and fallback"""

    # Prevent invalid page numbers
    if page_num < 1:
        return redirect(url_for('index', page_num=1))

    try:
        scraper = PageScraper()

        videos = retry_scrape(scraper.scrape_page, page_num)

        # If scraping failed OR no videos found
        if not videos:
            logging.warning(f"No videos found on page {page_num}")

            if page_num != 1:
                # Redirect to first page if not already there
                return redirect(url_for('index', page_num=1))

            return render_template(
                'index.html',
                error="No videos found.",
                videos=[],
                current_page=1
            )

        return render_template(
            'index.html',
            videos=videos,
            current_page=page_num
        )

    except Exception as e:
        logging.error(f"Unexpected error on index page: {e}")
        return redirect(url_for('index', page_num=1))


# ===============================
# VIDEO PAGE
# ===============================
@app.route('/video/<path:video_slug>')
def video_page(video_slug):
    """Individual video page with retry and fallback"""

    if not video_slug:
        return redirect(url_for('index'))

    try:
        scraper = VideoScraper()
        video_data = retry_scrape(scraper.scrape_video, video_slug)
        if not video_data:
            logging.warning(f"No video data found for slug: {video_slug}")
            return redirect(url_for('index'))

        return render_template('video.html', video=video_data)

    except Exception as e:
        logging.error(f"Error loading video page: {e}")
        return redirect(url_for('index'))


# ===============================
# API ENDPOINT
# ===============================
@app.route('/api/videos/page/<int:page_num>')
def api_videos(page_num):
    """API endpoint for AJAX loading with retry"""

    if page_num < 1:
        return jsonify({'success': False, 'error': 'Invalid page number'})

    try:
        scraper = PageScraper()
        videos = retry_scrape(scraper.scrape_page, page_num)

        if not videos:
            return jsonify({'success': False, 'error': 'No videos found'})

        return jsonify({'success': True, 'videos': videos})

    except Exception as e:
        logging.error(f"API error: {e}")
        return jsonify({'success': False, 'error': 'Internal server error'})

# ===============================
# CATEGORY / TAG PAGE
# ===============================
@app.route('/<path:custom_path>/')
@app.route('/<path:custom_path>/page/<int:page_num>/')
def filtered_listing(custom_path, page_num=1):

    if page_num < 1:
        return redirect(url_for('index'))

    try:
        scraper = PageScraper()

        videos = retry_scrape(
            scraper.scrape_page,
            page_num,
            custom_path
        )

        if not videos:
            return redirect(url_for('index'))

        return render_template(
            'index.html',
            videos=videos,
            current_page=page_num
        )

    except Exception as e:
        logging.error(f"Filtered page error: {e}")
        return redirect(url_for('index'))

# ===============================
# APP RUN
# ===============================
if __name__ == '__main__':
    app.run(debug=True)

