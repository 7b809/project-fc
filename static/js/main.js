// Main JavaScript file for interactive features (continued)

$(document).ready(function() {
    // Lazy loading for images
    $('img[data-src]').each(function() {
        var img = $(this);
        img.attr('src', img.data('src'));
    });

    // Video player controls and interactions
    initializeVideoPlayer();
    
    // Rating interaction (demonstration only)
    initializeRatingButtons();
    
    // Related videos loader
    loadRelatedVideos();
    
    // Infinite scroll for pagination (optional)
    var loading = false;
    var lastPage = false;

    $(window).scroll(function() {
        if (loading || lastPage) return;

        var scrollTop = $(window).scrollTop();
        var windowHeight = $(window).height();
        var documentHeight = $(document).height();

        if (scrollTop + windowHeight >= documentHeight - 200) {
            loadMoreVideos();
        }
    });

    function loadMoreVideos() {
        var currentPage = $('.pagination .current-page').text().replace('Page ', '');
        var nextPage = parseInt(currentPage) + 1;
        var nextPageLink = $('.pagination .next-page').attr('href');

        if (!nextPageLink) {
            lastPage = true;
            return;
        }

        loading = true;
        $('.videos-list').append('<div class="loading">Loading more videos...</div>');

        $.ajax({
            url: '/api/videos/page/' + nextPage,
            method: 'GET',
            success: function(response) {
                $('.loading').remove();
                
                if (response.success && response.videos.length > 0) {
                    appendVideos(response.videos);
                    updatePagination(nextPage, response.videos.length);
                } else {
                    lastPage = true;
                    $('.videos-list').append('<div class="no-more">No more videos</div>');
                }
                
                loading = false;
            },
            error: function() {
                $('.loading').remove();
                loading = false;
                lastPage = true;
            }
        });
    }

    function appendVideos(videos) {
        var html = '';
        
        videos.forEach(function(video) {
            // Format tags display
            var tagsHtml = '';
            if (video.tags && video.tags.length > 0) {
                tagsHtml = video.tags.slice(0, 3).map(tag => 
                    `<span class="tag">${tag.replace(/-/g, ' ')}</span>`
                ).join('');
            }
            
            html += `
                <article class="video-card" data-video-id="${video.id}" data-video-uid="${video.uid}">
                    <a href="/video/${video.slug}" class="video-link">
                        <div class="video-thumbnail">
                            <img src="${video.thumbnail}" alt="${video.title}" loading="lazy">
                            ${video.is_hd ? '<span class="hd-badge">HD</span>' : ''}
                            <div class="video-meta">
                                <span class="views"><i class="fa fa-eye"></i> ${formatViews(video.views)}</span>
                                <span class="duration"><i class="fa fa-clock"></i> ${formatDuration(video.duration)}</span>
                            </div>
                        </div>
                        <div class="rating-bar">
                            <div class="rating-bar-meter" style="width: ${video.rating}%"></div>
                            <i class="fa fa-thumbs-up"></i>
                            <span>${video.rating}%</span>
                        </div>
                        <h3 class="video-title">${video.title}</h3>
                        <div class="video-tags">
                            ${tagsHtml}
                        </div>
                    </a>
                </article>
            `;
        });
        
        $('.videos-list').append(html);
        
        // Re-initialize lazy loading for new images
        $('img[data-src]').each(function() {
            var img = $(this);
            if (!img.attr('src')) {
                img.attr('src', img.data('src'));
            }
        });
    }

    function updatePagination(nextPage, videoCount) {
        var currentPageLink = $('.pagination .current-page');
        var nextPageLink = $('.pagination .next-page');
        
        if (videoCount < 10) { // Assuming 10 items per page
            nextPageLink.remove();
        } else {
            currentPageLink.text('Page ' + nextPage);
            nextPageLink.attr('href', '/page/' + nextPage);
        }
    }

    function formatViews(views) {
        if (!views) return '0';
        if (views >= 1000000) {
            return (views / 1000000).toFixed(1) + 'M';
        } else if (views >= 1000) {
            return (views / 1000).toFixed(1) + 'K';
        }
        return views.toString();
    }

    function formatDuration(duration) {
        if (!duration) return '00:00';
        
        // If duration is already formatted, return as is
        if (typeof duration === 'string' && duration.includes(':')) {
            return duration;
        }
        
        // If duration is in seconds, format it
        if (typeof duration === 'number') {
            var hours = Math.floor(duration / 3600);
            var minutes = Math.floor((duration % 3600) / 60);
            var seconds = duration % 60;
            
            if (hours > 0) {
                return hours + ':' + padZero(minutes) + ':' + padZero(seconds);
            } else {
                return padZero(minutes) + ':' + padZero(seconds);
            }
        }
        
        return duration;
    }

    function padZero(num) {
        return num.toString().padStart(2, '0');
    }
});

function initializeVideoPlayer() {
    var video = document.getElementById('main-video');
    if (!video) return;
    
    // Store watch progress in localStorage (educational demonstration)
    video.addEventListener('timeupdate', function() {
        var videoId = window.location.pathname.split('/').pop();
        var progress = (video.currentTime / video.duration) * 100;
        
        if (progress > 5 && progress < 95) {
            localStorage.setItem('progress_' + videoId, progress);
        }
    });
    
    // Resume from last position if available
    video.addEventListener('loadedmetadata', function() {
        var videoId = window.location.pathname.split('/').pop();
        var savedProgress = localStorage.getItem('progress_' + videoId);
        
        if (savedProgress && confirm('Resume from where you left off?')) {
            var resumeTime = (savedProgress / 100) * video.duration;
            video.currentTime = resumeTime;
        }
    });
    
    // Keyboard controls
    $(document).keydown(function(e) {
        if (!video) return;
        
        switch(e.keyCode) {
            case 32: // Spacebar
                e.preventDefault();
                if (video.paused) {
                    video.play();
                } else {
                    video.pause();
                }
                break;
            case 39: // Right arrow
                e.preventDefault();
                video.currentTime += 10;
                break;
            case 37: // Left arrow
                e.preventDefault();
                video.currentTime -= 10;
                break;
            case 38: // Up arrow
                e.preventDefault();
                video.volume = Math.min(video.volume + 0.1, 1);
                break;
            case 40: // Down arrow
                e.preventDefault();
                video.volume = Math.max(video.volume - 0.1, 0);
                break;
            case 70: // F key for fullscreen
                e.preventDefault();
                if (document.fullscreenElement) {
                    document.exitFullscreen();
                } else {
                    video.requestFullscreen();
                }
                break;
        }
    });
}

function initializeRatingButtons() {
    // This is a demonstration - ratings don't actually get saved
    $('.rating-details .fa-thumbs-up, .rating-details .fa-thumbs-down').parent().click(function(e) {
        e.preventDefault();
        
        var $this = $(this);
        var isLike = $this.find('.fa-thumbs-up').length > 0;
        
        // Toggle active state
        $this.siblings().removeClass('active');
        $this.addClass('active');
        
        // Show feedback message
        var message = isLike ? 'Thanks for liking! (Demo only)' : 'Thanks for your feedback! (Demo only)';
        showNotification(message);
    });
}

function loadRelatedVideos() {
    var $relatedContainer = $('#related-videos');
    if ($relatedContainer.length === 0) return;
    
    // Simulate loading related videos
    setTimeout(function() {
        // Get current video tags from the page
        var currentTags = [];
        $('.video-tags .tag').each(function() {
            currentTags.push($(this).text().trim());
        });
        
        // In a real implementation, this would be an API call
        // For demo, we'll show placeholder content
        var relatedHtml = '<p class="placeholder-message">';
        relatedHtml += 'Related videos would be loaded based on tags: ';
        relatedHtml += currentTags.join(', ') + '</p>';
        
        $relatedContainer.html(relatedHtml);
    }, 1000);
}

function showNotification(message) {
    // Create notification element
    var $notification = $('<div class="notification"></div>')
        .text(message)
        .css({
            'position': 'fixed',
            'bottom': '20px',
            'right': '20px',
            'background': '#667eea',
            'color': 'white',
            'padding': '10px 20px',
            'border-radius': '4px',
            'box-shadow': '0 2px 4px rgba(0,0,0,0.2)',
            'z-index': '9999',
            'animation': 'slideIn 0.3s ease'
        });
    
    $('body').append($notification);
    
    // Remove after 3 seconds
    setTimeout(function() {
        $notification.fadeOut(300, function() {
            $(this).remove();
        });
    }, 3000);
}

// Add CSS animation for notifications
$('<style>')
    .prop('type', 'text/css')
    .html(`
        @keyframes slideIn {
            from {
                transform: translateX(100%);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
        
        .notification {
            transition: opacity 0.3s ease;
        }
        
        .rating-details .active {
            color: #667eea;
            font-weight: bold;
        }
        
        .rating-details .fa-thumbs-up.active {
            color: #4CAF50;
        }
        
        .rating-details .fa-thumbs-down.active {
            color: #f44336;
        }
        
        .no-more {
            grid-column: 1 / -1;
            text-align: center;
            padding: 2rem;
            color: #666;
            background: white;
            border-radius: 8px;
        }
        
        .placeholder-message {
            grid-column: 1 / -1;
            text-align: center;
            padding: 2rem;
            background: #f9f9f9;
            border-radius: 8px;
            color: #666;
            font-style: italic;
        }
    `)
    .appendTo('head');