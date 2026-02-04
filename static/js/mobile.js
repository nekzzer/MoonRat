document.addEventListener('DOMContentLoaded', function() {
    document.body.style.overflowX = 'hidden';
    document.documentElement.style.overflowX = 'hidden';
    
    const allElements = document.querySelectorAll('*:not(nav)');
    allElements.forEach(el => {
        if (el.tagName !== 'NAV') {
            el.style.maxWidth = '100%';
        }
    });
});
function scrollActiveTabIntoView() {
    if (window.innerWidth <= 768) {
        const activeTab = document.querySelector('.nav-btn[data-active="true"]');
        if (activeTab) {
            setTimeout(() => {
                activeTab.scrollIntoView({
                    behavior: 'smooth',
                    block: 'nearest',
                    inline: 'center'
                });
            }, 100);
        }
    }
}

window.addEventListener('load', function() {
    const originalSwitchTab = window.switchTab;
    if (originalSwitchTab) {
        window.switchTab = function(tabId) {
            originalSwitchTab(tabId);
            scrollActiveTabIntoView();
        };
    }
});


function selectClientMobile(id) {
    selectClient(id);
    
    if (window.innerWidth <= 768) {
        const sidebar = document.getElementById('sidebar');
        const overlay = document.getElementById('sidebarOverlay');
        if (sidebar) {
            sidebar.classList.remove('mobile-open');
            if (overlay) overlay.classList.remove('active');
            document.body.style.overflow = '';
        }
    }
}


let lastTouchEnd = 0;
document.addEventListener('touchend', function(e) {
    const now = Date.now();
    if (now - lastTouchEnd <= 300) {
        e.preventDefault();
    }
    lastTouchEnd = now;
}, false);


window.addEventListener('orientationchange', function() {
    setTimeout(function() {
        window.scrollTo(0, 0);
    }, 100);
});


if ('ontouchstart' in window) {
    document.querySelectorAll('.custom-scroll').forEach(el => {
        el.style.webkitOverflowScrolling = 'touch';
    });
}


if (!document.querySelector('meta[name="viewport"]')) {
    const meta = document.createElement('meta');
    meta.name = 'viewport';
    meta.content = 'width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no';
    document.head.appendChild(meta);
}

document.addEventListener('DOMContentLoaded', function() {
    const sidebar = document.getElementById('sidebar');
    if (sidebar && window.innerWidth <= 768) {
        sidebar.addEventListener('click', function(e) {
            const rect = sidebar.getBoundingClientRect();
            const closeButtonArea = {
                top: rect.top + 16,
                right: rect.right - 16,
                bottom: rect.top + 56,
                left: rect.right - 56
            };
            
            if (e.clientX >= closeButtonArea.left && 
                e.clientX <= closeButtonArea.right &&
                e.clientY >= closeButtonArea.top && 
                e.clientY <= closeButtonArea.bottom) {
                toggleMobileSidebar();
            }
        });
    }
});


if ('ontouchstart' in window) {
    document.querySelectorAll('.custom-scroll, .tab-content, #clientList').forEach(el => {
        el.style.webkitOverflowScrolling = 'touch';
    });
}


let touchStartY = 0;
document.addEventListener('touchstart', function(e) {
    touchStartY = e.touches[0].clientY;
}, { passive: true });

document.addEventListener('touchmove', function(e) {
    const touchY = e.touches[0].clientY;
    const touchDiff = touchY - touchStartY;
    
    if (touchDiff > 0 && window.scrollY === 0) {
        e.preventDefault();
    }
}, { passive: false });
