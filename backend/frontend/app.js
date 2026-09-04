const API_BASE_URL = '/api';
let currentUser = null;
let allChallenges = [];
let filteredChallenges = [];
let communityChallenges = [];
let communitySortMode = 'newest';
let challengeCommentsState = {};
let appConfig = {
  turnstile_enabled: false,
  site_key: '0x4AAAAAAEluDz4B8bvFcmsF'
};

const REPORT_REASONS = [
  { id: 'spam', label: 'Spam or misleading', description: 'Duplicate, spam, or irrelevant content' },
  { id: 'policy', label: 'Policy violation', description: 'Violates platform rules or terms' },
  { id: 'inappropriate', label: 'Inappropriate content', description: 'Offensive, violent, or explicit material' },
  { id: 'copyright', label: 'Copyright issue', description: 'Unauthorized use of copyrighted material' },
  { id: 'other', label: 'Other', description: 'Other moderation concern' }
];

let selectedReportReason = null;
let reportChallengeId = null;
let reportContext = 'challenge';
let reportCommentId = null;

const badgeCatalog = [
  {
    id: 'rookie',
    label: 'Rookie Analyst',
    icon: 'fa-seedling',
    description: 'Your first verified case solved.',
    criteria: (user) => Number(user?.solved_count || 0) >= 1,
    tone: 'bronze'
  },
  {
    id: 'resolver',
    label: 'Case Resolver',
    icon: 'fa-crosshairs',
    description: 'Solve 3 or more cases.',
    criteria: (user) => Number(user?.solved_count || 0) >= 3,
    tone: 'silver'
  },
  {
    id: 'investigator',
    label: 'Elite Investigator',
    icon: 'fa-medal',
    description: 'Reach 1,000 rank points.',
    criteria: (user) => Number(user?.rank_points || 0) >= 1000,
    tone: 'gold'
  },
  {
    id: 'collector',
    label: 'Coin Collector',
    icon: 'fa-coins',
    description: 'Accumulate 200 or more coins.',
    criteria: (user) => Number(user?.coins || 0) >= 200,
    tone: 'cyan'
  },
  {
    id: 'builder',
    label: 'Community Builder',
    icon: 'fa-users',
    description: 'Publish a challenge to the community board.',
    criteria: () => false,
    tone: 'violet'
  },
  {
    id: 'guardian',
    label: 'Platform Guardian',
    icon: 'fa-shield-halved',
    description: 'Admin or moderator access granted.',
    criteria: (user) => Boolean(user?.is_admin),
    tone: 'indigo'
  }
];

const page = document.body ? document.body.dataset.page : '';

function buildTagPills(tagsText, fallbackLabel = 'Open') {
  const values = (tagsText || '')
    .split(',')
    .map((tag) => tag.trim())
    .filter(Boolean);

  const finalValues = values.length ? values : [fallbackLabel];

  return finalValues.slice(0, 3).map((tag) => `
    <span class="mini-tag">${escapeHtml(tag)}</span>
  `).join('');
}

function getUserBadges(user) {
  const safeUser = user || { solved_count: 0, rank_points: 0, coins: 0, is_admin: false };
  return badgeCatalog.map((badge) => ({
    ...badge,
    unlocked: Boolean(badge.criteria(safeUser))
  }));
}

function renderBadgeShowcase() {
  const showcase = document.getElementById('badgeShowcase');
  if (!showcase) return;

  const badges = badgeCatalog.map((badge) => {
    const unlocked = badge.criteria(currentUser || { solved_count: 0, rank_points: 0, coins: 0, is_admin: false });
    return `
      <div class="badge-card ${unlocked ? 'unlocked' : 'locked'}">
        <div class="badge-icon ${badge.tone}"><i class="fa-solid ${badge.icon}"></i></div>
        <div class="badge-copy">
          <h3>${badge.label}</h3>
          <p>${badge.description}</p>
        </div>
        <span class="badge-status">${unlocked ? 'Unlocked' : 'Locked'}</span>
      </div>
    `;
  }).join('');

  showcase.innerHTML = badges;
}

function renderUserBadges() {
  const badgeList = document.getElementById('profileBadges');
  if (!badgeList) return;

  const badges = getUserBadges(currentUser);
  const unlocked = badges.filter((badge) => badge.unlocked);

  if (!unlocked.length) {
    badgeList.innerHTML = '<span class="tag">No badges yet — start solving to unlock your first case badge.</span>';
    return;
  }

  badgeList.innerHTML = unlocked.map((badge) => `
    <span class="badge-pill badge-${badge.tone}"><i class="fa-solid ${badge.icon}"></i> ${badge.label}</span>
  `).join('');
}

function safeGetById(id) {
  return document.getElementById(id);
}

function safeSetValue(id, value) {
  const element = document.getElementById(id);
  if (element) {
    element.value = value;
  }
}

async function loadAppConfig() {
  try {
    const response = await fetch(`${API_BASE_URL}/config`);
    if (!response.ok) {
      throw new Error('Failed to load app config');
    }
    const config = await response.json();
    appConfig = {
      turnstile_enabled: Boolean(config.turnstile_enabled),
      site_key: String(config.site_key || '0x4AAAAAAEluDz4B8bvFcmsF')
    };
  } catch (error) {
    appConfig = {
      turnstile_enabled: true,
      site_key: '0x4AAAAAAEluDz4B8bvFcmsF'
    };
  }
}

function renderTurnstileWidgets() {
  const widgets = document.querySelectorAll('.turnstile-widget');
  if (!widgets.length) return;

  if (!appConfig.turnstile_enabled || !appConfig.site_key) {
    widgets.forEach((widget) => {
      widget.style.display = 'none';
      const hiddenTokenInput = widget.nextElementSibling;
      if (hiddenTokenInput && hiddenTokenInput.tagName === 'INPUT') {
        hiddenTokenInput.value = '';
      }
    });
    return;
  }

  if (!window.turnstile) {
    window.setTimeout(renderTurnstileWidgets, 500);
    widgets.forEach((widget) => {
      widget.style.display = 'none';
    });
    return;
  }

  widgets.forEach((widget) => {
    const callbackName = widget.dataset.callback || '';
    const callback = window[callbackName];
    widget.dataset.sitekey = appConfig.site_key;
    widget.style.display = 'block';
    if (widget.dataset.rendered === 'true') return;

    window.turnstile.render(widget, {
      sitekey: appConfig.site_key,
      callback: typeof callback === 'function' ? callback : undefined,
      theme: widget.dataset.theme || 'dark'
    });
    widget.dataset.rendered = 'true';
  });
}

function showAuthNotice(message) {
  const banner = safeGetById('loginMessage');
  if (banner) {
    banner.textContent = message;
    banner.classList.add('error');
    banner.classList.remove('success');
  }
  if (message) {
    showToast(`🚫 ${message}`, 'error');
  }
}

function showLoadingScreen() {
  if (document.getElementById('cyberLoadingScreen')) return;

  const screen = document.createElement('div');
  screen.id = 'cyberLoadingScreen';
  screen.className = 'cyber-loading-screen';
  screen.setAttribute('role', 'status');
  screen.setAttribute('aria-live', 'polite');
  screen.dataset.startedAt = String(Date.now());
  screen.innerHTML = `
    <div class="cyber-loader" aria-hidden="true">
      <span class="cyber-loader-ring"></span>
      <span class="cyber-loader-core"><i class="fa-solid fa-user-secret"></i></span>
    </div>
    <div class="cyber-loader-title">ESTABLISHING SECURE LINK</div>
    <div class="cyber-loader-status"><span></span><span></span><span></span></div>
    <div class="cyber-loader-subtitle">Decrypting intelligence workspace...</div>
  `;
  document.body.appendChild(screen);
}

function hideLoadingScreen() {
  const screen = document.getElementById('cyberLoadingScreen');
  if (!screen) return;
  const startedAt = Number(screen.dataset.startedAt || Date.now());
  const remaining = Math.max(0, 450 - (Date.now() - startedAt));
  window.setTimeout(() => {
    screen.classList.add('is-hidden');
    window.setTimeout(() => screen.remove(), 280);
  }, remaining);
}

document.addEventListener('DOMContentLoaded', async () => {
  showLoadingScreen();
  try {
    await loadAppConfig();
    renderTurnstileWidgets();
  } catch (error) {
    console.warn('Failed to init app config', error);
  }
  initializePage().finally(hideLoadingScreen);
});

async function initializePage() {
  bindGlobalEvents();
  await loadUser();

  if (page === 'landing') {
    updateLandingAuthState();
    initNetworkAnimation();
    return;
  }

  if (page === 'login' || page === 'signup') {
    if (currentUser) {
      window.location.href = 'dashboard.html';
      return;
    }
    const pendingAuthError = sessionStorage.getItem('cipherpoint_auth_error');
    if (pendingAuthError) {
      showAuthNotice(pendingAuthError);
      sessionStorage.removeItem('cipherpoint_auth_error');
    }
    initNetworkAnimation();
    setupForgotPassword();
    renderTurnstileWidgets();
    return;
  }

  if (page === 'dashboard') {
    if (!currentUser) {
      window.location.href = 'login.html';
      return;
    }
    setDashboardStats();
    await loadChallenges();
    await loadCommunityChallenges();
    if (currentUser && currentUser.is_admin) {
      await loadModerationQueue();
    }
    await renderTopChallenges();
    await renderRecentActivity();
    await loadLeaderboard();
    return;
  }

  if (page === 'community') {
    if (!currentUser) {
      window.location.href = 'login.html';
      return;
    }
    await loadCommunityChallenges();

    const communityCreateBtn = safeGetById('communityCreateBtn');
    if (communityCreateBtn) {
      communityCreateBtn.addEventListener('click', () => {
        const modal = safeGetById('communityModal');
        if (modal) modal.classList.add('active');
      });
    }
    return;
  }

  if (page === 'profile') {
    if (!currentUser) {
      window.location.href = 'login.html';
      return;
    }
    await loadProfile();
    return;
  }

  if (page === 'settings') {
    if (!currentUser) {
      window.location.href = 'login.html';
      return;
    }
    await loadSettings();
    await loadTelegramStatus();
    setupSettingsForms();
    setupTelegramConnect();
    startTelegramConnectionPolling();
    return;
  }

  if (page === 'leaderboard') {
    await loadUser();
    await loadFullLeaderboard();
    return;
  }

  if (page === 'challenge-detail') {
    if (!currentUser) {
      window.location.href = 'login.html';
      return;
    }
    const params = new URLSearchParams(window.location.search);
    const challengeId = Number(params.get('id'));
    if (challengeId) {
      await loadChallengeDetailPage(challengeId);
    }
    return;
  }

  if (page === 'comments') {
    if (!currentUser) {
      window.location.href = 'login.html';
      return;
    }
    const params = new URLSearchParams(window.location.search);
    const challengeId = Number(params.get('id'));
    if (challengeId) {
      await loadCommentsPage(challengeId);
      setupCommentsPage();
    }
    return;
  }
}

function bindGlobalEvents() {
  const authButton = safeGetById('authBtn');
  if (authButton) {
    authButton.addEventListener('click', () => {
      if (currentUser) {
        logout();
      } else {
        window.location.href = 'login.html';
      }
    });
  }

  const logoutButtons = document.querySelectorAll('#logoutBtn');
  logoutButtons.forEach((logoutButton) => {
    logoutButton.addEventListener('click', () => {
      logout();
    });
  });

  const sidebarToggle = safeGetById('sidebarToggle');
  if (sidebarToggle) {
    sidebarToggle.addEventListener('click', () => {
      const sidebar = safeGetById('sidebar');
      if (sidebar) {
        sidebar.classList.toggle('collapsed');
        const icon = sidebarToggle.querySelector('i');
        if (icon) {
          icon.className = sidebar.classList.contains('collapsed')
            ? 'fa-solid fa-angle-right'
            : 'fa-solid fa-angle-left';
        }
      }
    });
  }

  const menuToggle = safeGetById('menuToggle');
  const sidebar = safeGetById('sidebar');
  if (menuToggle && sidebar) {
    menuToggle.addEventListener('click', () => {
      const isOpen = sidebar.classList.contains('mobile-open');
      if (isOpen) {
        sidebar.classList.remove('mobile-open');
        const overlay = safeGetById('sidebarOverlay');
        if (overlay) overlay.classList.remove('active');
        const icon = menuToggle.querySelector('i');
        if (icon) icon.className = 'fa-solid fa-bars';
      } else {
        sidebar.classList.add('mobile-open');
        const overlay = safeGetById('sidebarOverlay');
        if (overlay) overlay.classList.add('active');
        const icon = menuToggle.querySelector('i');
        if (icon) icon.className = 'fa-solid fa-xmark';
      }
    });
  }

  const overlay = safeGetById('sidebarOverlay');
  if (overlay) {
    overlay.addEventListener('click', () => {
      const sidebar = safeGetById('sidebar');
      if (sidebar) {
        sidebar.classList.remove('mobile-open');
        overlay.classList.remove('active');
        const icon = menuToggle.querySelector('i');
        if (icon) icon.className = 'fa-solid fa-bars';
      }
    });
  }

  const sidebarLinks = document.querySelectorAll('.sidebar-link');
  sidebarLinks.forEach((link) => {
    link.addEventListener('click', () => {
      const sidebar = safeGetById('sidebar');
      const overlay = safeGetById('sidebarOverlay');
      if (sidebar) sidebar.classList.remove('mobile-open');
      if (overlay) overlay.classList.remove('active');
      const icon = menuToggle.querySelector('i');
      if (icon) icon.className = 'fa-solid fa-bars';
    });
  });

  const loginForm = safeGetById('loginForm');
  if (loginForm) {
    loginForm.addEventListener('submit', handleLogin);
  }

  const otpLoginForm = safeGetById('otpLoginForm');
  if (otpLoginForm) {
    otpLoginForm.addEventListener('submit', handleOtpVerifySubmit);
  }

  const toggleOtpBtn = safeGetById('toggleOtpBtn');
  if (toggleOtpBtn) {
    toggleOtpBtn.addEventListener('click', () => {
      const loginFormEl = safeGetById('loginForm');
      const otpForm = safeGetById('otpLoginForm');
      if (loginFormEl) loginFormEl.style.display = 'none';
      if (otpForm) otpForm.style.display = 'block';
    });
  }

  const otpBackBtn = safeGetById('otpBackToPasswordBtn');
  if (otpBackBtn) {
    otpBackBtn.addEventListener('click', () => {
      const loginFormEl = safeGetById('loginForm');
      const otpForm = safeGetById('otpLoginForm');
      if (otpForm) otpForm.style.display = 'none';
      if (loginFormEl) loginFormEl.style.display = 'block';
    });
  }

  const otpRequestBtn = safeGetById('otpRequestBtn');
  if (otpRequestBtn) {
    otpRequestBtn.addEventListener('click', handleOtpRequest);
  }

  const otpResendBtn = safeGetById('otpResendBtn');
  if (otpResendBtn) {
    otpResendBtn.addEventListener('click', handleOtpRequest);
  }

  const signupForm = safeGetById('signupForm');
  if (signupForm) {
    signupForm.addEventListener('submit', handleSignup);
  }

  // Use event delegation for password toggles - works for both initial DOM
  // and any modals that were already in the page on load
  document.addEventListener('click', (event) => {
    const btn = event.target.closest('.password-toggle');
    if (!btn) return;
    event.preventDefault();
    event.stopPropagation();
    const wrapper = btn.closest('.password-field');
    const input = wrapper?.querySelector('input');
    if (!input) return;
    const isPassword = input.type === 'password';
    input.type = isPassword ? 'text' : 'password';
    const icon = btn.querySelector('i');
    if (icon) {
      icon.className = isPassword ? 'fa-solid fa-eye-slash' : 'fa-solid fa-eye';
    }
    // Keep focus on the input so the user can keep typing
    setTimeout(() => input.focus(), 0);
  });

  const signupPassword = safeGetById('signupPassword');
  const passwordStrength = safeGetById('passwordStrength');
  if (signupPassword && passwordStrength) {
    signupPassword.addEventListener('input', () => {
      const val = signupPassword.value;
      let strength = 'weak';
      if (val.length >= 8 && /[A-Z]/.test(val) && /[0-9]/.test(val) && /[^A-Za-z0-9]/.test(val)) {
        strength = 'strong';
      } else if (val.length >= 6) {
        strength = 'medium';
      }
      passwordStrength.className = `password-strength ${strength}`;
      const text = passwordStrength.querySelector('.strength-text');
      if (text) {
        text.textContent = val.length === 0 ? 'Enter password' : strength === 'weak' ? 'Weak' : strength === 'medium' ? 'Medium' : 'Strong';
      }
    });
  }

  document.querySelectorAll('.filter-btn').forEach((button) => {
    button.addEventListener('click', (event) => {
      const filter = event.currentTarget.dataset.filter || 'all';
      filterChallenges(filter);
    });
  });

  document.querySelectorAll('.community-sort').forEach((button) => {
    button.addEventListener('click', (event) => {
      communitySortMode = event.currentTarget.dataset.sort || 'newest';
      document.querySelectorAll('.community-sort').forEach((item) => {
        item.classList.toggle('active', item.dataset.sort === communitySortMode);
      });
      renderCommunityChallenges();
    });
  });

  const challengeSearch = safeGetById('challengeSearch');
  if (challengeSearch) {
    // Debounced so we don't re-render on every keystroke
    challengeSearch.addEventListener('input', (event) => {
      clearTimeout(challengeSearch._debounce);
      const value = event.target.value;
      const clearBtn = safeGetById('challengeSearchClear');
      if (clearBtn) clearBtn.hidden = value.length === 0;
      challengeSearch._debounce = setTimeout(() => {
        handleSearch(value);
      }, 180);
    });
  }

  const challengeSearchClear = safeGetById('challengeSearchClear');
  if (challengeSearchClear && challengeSearch) {
    challengeSearchClear.addEventListener('click', () => {
      challengeSearch.value = '';
      challengeSearchClear.hidden = true;
      challengeSearch.focus();
      handleSearch('');
    });
  }

  const searchBox = safeGetById('searchBox');
  if (searchBox) {
    searchBox.addEventListener('input', (event) => handleSearch(event.target.value));
  }

  const bonusButton = safeGetById('bonusBtn');
  if (bonusButton) {
    bonusButton.addEventListener('click', claimDailyBonus);
  }

  const claimBonusButton = safeGetById('claimBonusBtn');
  if (claimBonusButton) {
    claimBonusButton.addEventListener('click', claimDailyBonus);
  }

  const communityCreateBtn = safeGetById('communityCreateBtn');
  if (communityCreateBtn) {
    communityCreateBtn.addEventListener('click', () => {
      const modal = safeGetById('communityModal');
      if (modal) modal.classList.add('active');
    });
  }

  const communityForm = safeGetById('communityForm');
  if (communityForm) {
    communityForm.addEventListener('submit', handleCommunityChallengeSubmit);
  }

  const communityMedia = safeGetById('communityMedia');
  if (communityMedia) {
    communityMedia.addEventListener('change', handleCommunityMediaChange);
  }

  document.querySelectorAll('.modal-close').forEach((button) => {
    button.addEventListener('click', () => {
      const modal = button.closest('.modal');
      if (modal) modal.classList.remove('active');
    });
  });

  document.querySelectorAll('[data-confirm-close]').forEach((button) => {
    button.addEventListener('click', () => closeConfirmDeleteModal());
  });

  const confirmDeleteBtn = safeGetById('confirmDeleteBtn');
  if (confirmDeleteBtn) {
    const pageType = document.body?.dataset?.page || '';
    if (pageType === 'settings') {
      confirmDeleteBtn.addEventListener('click', deleteAccount);
    } else {
      confirmDeleteBtn.addEventListener('click', performChallengeDelete);
    }
  }

  const confirmCancelBtn = safeGetById('confirmCancelBtn');
  if (confirmCancelBtn) {
    confirmCancelBtn.addEventListener('click', closeConfirmDeleteModal);
  }

  const submitReportBtn = safeGetById('submitReportBtn');
  if (submitReportBtn) {
    submitReportBtn.addEventListener('click', submitReport);
  }

  const commentInput = safeGetById('commentInput');
  if (commentInput) {
    commentInput.addEventListener('input', (event) => {
      const counter = safeGetById('commentCharCount');
      if (counter) counter.textContent = `${event.target.value.length} / 2000`;
    });
  }

  const editProfileBtn = safeGetById('editProfileBtn');
  if (editProfileBtn) {
    editProfileBtn.addEventListener('click', openProfileEditModal);
  }

  document.addEventListener('click', (event) => {
    if (event.target && event.target.classList.contains('modal')) {
      event.target.classList.remove('active');
    }

    if (event.target && event.target.id === 'hintModal') {
      closeHintModal();
    }

    if (!event.target.closest('.challenge-options-dropdown')) {
      document.querySelectorAll('.dropdown-menu').forEach(m => m.style.display = 'none');
    }
  });
}

function setUserDisplayState() {
  const authButton = safeGetById('authBtn');
  if (authButton) {
    authButton.textContent = currentUser ? `Logout (${currentUser.username})` : 'Sign In';
    authButton.classList.toggle('logout', Boolean(currentUser));
  }

  const coinValue = safeGetById('coinValue');
  const rankValue = safeGetById('rankValue');
  const solvedValue = safeGetById('solvedValue');
  const levelValue = safeGetById('levelValue');

  const coinCount = currentUser ? Number(currentUser.coins || 0) : 0;
  const rankPoints = currentUser ? Number(currentUser.rank_points || 0) : 0;
  const solvedCount = currentUser ? Number(currentUser.solved_count || 0) : 0;

  if (coinValue) coinValue.textContent = coinCount;
  if (rankValue) rankValue.textContent = rankPoints;
  if (solvedValue) solvedValue.textContent = solvedCount;
  if (levelValue) levelValue.textContent = rankPoints;

  const profileCoins = safeGetById('profileCoins');
  if (profileCoins && currentUser) profileCoins.textContent = coinCount;

  const profilePoints = safeGetById('profilePoints');
  if (profilePoints && currentUser) profilePoints.textContent = rankPoints;

  const profileSolved = safeGetById('profileSolved');
  if (profileSolved && currentUser) profileSolved.textContent = solvedCount;

  const overviewCoins = safeGetById('overviewCoins');
  if (overviewCoins && currentUser) overviewCoins.textContent = coinCount;

  const overviewPoints = safeGetById('overviewPoints');
  if (overviewPoints && currentUser) overviewPoints.textContent = rankPoints;

  const overviewSolved = safeGetById('overviewSolved');
  if (overviewSolved && currentUser) overviewSolved.textContent = solvedCount;

  const profileUsername = safeGetById('profileUsername');
  if (profileUsername && currentUser) profileUsername.textContent = currentUser.username;

  const profileEmail = safeGetById('profileEmail');
  if (profileEmail && currentUser) profileEmail.textContent = currentUser.email || '-';

  updateBonusButtonState();
  updateModerationWidget();
  renderUserBadges();
  renderBadgeShowcase();
}

function updateModerationWidget() {
  const moderationWidget = safeGetById('moderationQueue');
  if (!moderationWidget) return;

  const isAdmin = Boolean(currentUser && currentUser.is_admin);
  moderationWidget.style.display = isAdmin ? 'block' : 'none';
}

function getBonusClaimKey() {
  const today = new Date();
  return today.toISOString().slice(0, 10);
}

function getBonusStorageKey() {
  const userKey = currentUser ? (currentUser.id || currentUser.username || 'guest') : 'guest';
  return `cipherpoint_bonus_claimed_${userKey}`;
}

function updateBonusButtonState() {
  const bonusButton = safeGetById('bonusBtn') || safeGetById('claimBonusBtn');
  if (!bonusButton) return;

  const claimedKey = localStorage.getItem(getBonusStorageKey());
  const serverClaimedAt = currentUser?.daily_bonus_claimed_at;
  const isClaimedToday = claimedKey === getBonusClaimKey()
    || (serverClaimedAt && new Date(serverClaimedAt).toISOString().slice(0, 10) === getBonusClaimKey());
  const hasUser = Boolean(currentUser);

  bonusButton.disabled = !hasUser || isClaimedToday;
  bonusButton.style.opacity = !hasUser || isClaimedToday ? '0.6' : '1';
  bonusButton.style.cursor = !hasUser || isClaimedToday ? 'not-allowed' : 'pointer';

  if (isClaimedToday) {
    bonusButton.textContent = 'Daily bonus claimed';
  } else {
    bonusButton.textContent = 'Claim 10 coins';
  }
}

function updateLandingAuthState() {
  const loginButton = document.querySelector('a[href="login.html"]');
  const signupButton = document.querySelector('a[href="signup.html"]');

  if (currentUser) {
    if (loginButton) loginButton.textContent = 'Dashboard';
    if (signupButton) signupButton.textContent = 'Profile';
    if (loginButton) loginButton.href = 'dashboard.html';
    if (signupButton) signupButton.href = 'profile.html';
  }
}

function setDashboardStats() {
  const coinValue = safeGetById('coinValue');
  const rankValue = safeGetById('rankValue');
  const solvedValue = safeGetById('solvedValue');

  if (currentUser) {
    if (coinValue) coinValue.textContent = Number(currentUser.coins || 0);
    if (rankValue) rankValue.textContent = Number(currentUser.rank_points || 0);
    if (solvedValue) solvedValue.textContent = Number(currentUser.solved_count || 0);
  }
}

async function loadUser() {
  const savedUser = localStorage.getItem('user');
  const token = localStorage.getItem('token');

  if (!savedUser || !token) {
    currentUser = null;
    setUserDisplayState();
    return null;
  }

  try {
    currentUser = JSON.parse(savedUser);
    const response = await fetch(`${API_BASE_URL}/auth/me`, {
      headers: {
        Authorization: `Bearer ${token}`
      }
    });

    if (response.ok) {
      const profile = await response.json();
      currentUser = { ...currentUser, ...profile };
      localStorage.setItem('user', JSON.stringify(currentUser));
      setUserDisplayState();
      return currentUser;
    }

    const errorData = await response.json().catch(() => ({}));
    if (response.status === 403) {
      const message = errorData.detail || 'Your account has been suspended.';
      currentUser = null;
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      sessionStorage.setItem('cipherpoint_auth_error', message);
      showToast(`🚫 ${message}`, 'error');
      window.location.href = 'login.html';
      return null;
    }

    throw new Error(errorData.detail || 'Invalid token');
  } catch (error) {
    currentUser = null;
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setUserDisplayState();
    return null;
  }
}

function logout() {
  currentUser = null;
  localStorage.removeItem('token');
  localStorage.removeItem('user');
  setUserDisplayState();
  showToast('✅ Logged out successfully', 'success');
}

async function handleLogin(event) {
  event.preventDefault();

  const username = safeGetById('loginUsername')?.value.trim();
  const password = safeGetById('loginPassword')?.value;
  const turnstileToken = safeGetById('loginTurnstileToken')?.value;
  const messageBox = safeGetById('loginMessage');

  if (!username || !password) {
    if (messageBox) {
      messageBox.textContent = 'Username and password are required';
      messageBox.className = 'form-message-inline error';
    }
    return;
  }

  try {
    const response = await fetch(`${API_BASE_URL}/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ username, password, turnstile_token: turnstileToken || null })
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      const errorMessage = data.detail || (
        response.status === 403
          ? 'Security verification failed. Please complete the Cloudflare check.'
          : 'Login failed'
      );
      if (messageBox) {
        messageBox.textContent = errorMessage;
        messageBox.className = 'form-message-inline error';
      }
      showToast(`🚫 ${errorMessage}`, 'error');
      if (window.turnstile) {
        try { window.turnstile.reset(); } catch (e) {}
      }
      return;
    }

    currentUser = data;
    localStorage.setItem('token', data.access_token);
    localStorage.setItem('user', JSON.stringify(data));
    setUserDisplayState();

    if (messageBox) {
      messageBox.textContent = 'Login successful';
      messageBox.className = 'form-message-inline success';
    }

    showToast('✅ Login successful', 'success');
    window.location.href = 'dashboard.html';
  } catch (error) {
    if (messageBox) {
      messageBox.textContent = 'Network error. Please try again.';
      messageBox.className = 'form-message-inline error';
    }
    showToast('❌ Network error', 'error');
  }
}

async function handleOtpRequest() {
  const chatId = safeGetById('otpChatId')?.value.trim();
  const turnstileToken = safeGetById('otpTurnstileToken')?.value;
  const requestMessageEl = safeGetById('otpRequestMessage');
  const requestBtn = safeGetById('otpRequestBtn');
  const verifySection = safeGetById('otpVerifySection');
  const codeInput = safeGetById('otpCodeInput');
  const verifyMessageEl = safeGetById('otpVerifyMessage');

  if (!chatId) {
    if (requestMessageEl) {
      requestMessageEl.textContent = 'Please enter your Telegram chat ID';
      requestMessageEl.className = 'form-message show error';
    }
    return;
  }

  if (requestBtn) requestBtn.disabled = true;
  if (requestMessageEl) {
    requestMessageEl.textContent = 'Sending OTP to Telegram...';
    requestMessageEl.className = 'form-message show';
  }

  try {
    const response = await fetch(`${API_BASE_URL}/auth/login/otp/request`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, turnstile_token: turnstileToken || null })
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      const errorMessage = response.status === 403
        ? 'Your account has been suspended.'
        : (data.detail || 'Unable to send OTP');
      if (requestMessageEl) {
        requestMessageEl.textContent = errorMessage;
        requestMessageEl.className = 'form-message show error';
      }
      if (response.status === 403) {
        showToast('🚫 Your account has been suspended.', 'error');
      }
      if (window.turnstile) {
        try { window.turnstile.reset(); } catch (e) {}
      }
      return;
    }

    if (requestMessageEl) {
      requestMessageEl.textContent = data.message || 'OTP sent! Check your Telegram.';
      requestMessageEl.className = 'form-message show success';
    }
    if (verifySection) verifySection.style.display = 'block';
    if (codeInput) {
      codeInput.value = '';
      codeInput.focus();
    }
    if (verifyMessageEl) {
      verifyMessageEl.textContent = '';
      verifyMessageEl.className = 'form-message';
    }
    showToast('📨 OTP sent to your Telegram', 'success');
  } catch (error) {
    if (requestMessageEl) {
      requestMessageEl.textContent = 'Network error. Please try again.';
      requestMessageEl.className = 'form-message show error';
    }
    showToast('❌ Network error', 'error');
  } finally {
    if (requestBtn) requestBtn.disabled = false;
  }
}

async function handleOtpVerifySubmit(event) {
  event.preventDefault();

  const chatId = safeGetById('otpChatId')?.value.trim();
  const otp = safeGetById('otpCodeInput')?.value.trim();
  const verifyMessageEl = safeGetById('otpVerifyMessage');

  if (!chatId || !otp) {
    if (verifyMessageEl) {
      verifyMessageEl.textContent = 'Chat ID and OTP are required';
      verifyMessageEl.className = 'form-message show error';
    }
    return;
  }

  if (!/^\d{6}$/.test(otp)) {
    if (verifyMessageEl) {
      verifyMessageEl.textContent = 'OTP must be exactly 6 digits';
      verifyMessageEl.className = 'form-message show error';
    }
    return;
  }

  try {
    const response = await fetch(`${API_BASE_URL}/auth/login/otp/verify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: chatId, otp })
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      const errorMessage = response.status === 403
        ? 'Your account has been suspended.'
        : (data.detail || 'OTP verification failed');
      if (verifyMessageEl) {
        verifyMessageEl.textContent = errorMessage;
        verifyMessageEl.className = 'form-message show error';
      }
      showToast(`❌ ${errorMessage}`, 'error');
      return;
    }

    currentUser = data;
    localStorage.setItem('token', data.access_token);
    localStorage.setItem('user', JSON.stringify(data));
    setUserDisplayState();

    if (verifyMessageEl) {
      verifyMessageEl.textContent = 'Login successful';
      verifyMessageEl.className = 'form-message show success';
    }
    showToast('✅ Login successful via Telegram OTP', 'success');
    window.location.href = 'dashboard.html';
  } catch (error) {
    if (verifyMessageEl) {
      verifyMessageEl.textContent = 'Network error. Please try again.';
      verifyMessageEl.className = 'form-message show error';
    }
    showToast('❌ Network error', 'error');
  }
}

function onTurnstileSuccessOtp(token) {
  const input = safeGetById('otpTurnstileToken');
  if (input) input.value = token || '';
}

async function handleSignup(event) {
  event.preventDefault();

  const username = safeGetById('signupUsername')?.value.trim();
  const email = safeGetById('signupEmail')?.value.trim();
  const password = safeGetById('signupPassword')?.value;
  const confirmPassword = safeGetById('signupConfirm')?.value;
  const turnstileToken = safeGetById('signupTurnstileToken')?.value;
  const messageBox = safeGetById('signupMessage');

  if (!username || !email || !password) {
    if (messageBox) {
      messageBox.textContent = 'All fields are required';
      messageBox.className = 'form-message-inline error';
    }
    return;
  }

  if (!/^[A-Za-z0-9_.-]{3,32}$/.test(username)) {
    if (messageBox) {
      messageBox.textContent = 'Username must be 3-32 chars (letters, digits, . _ -)';
      messageBox.className = 'form-message-inline error';
    }
    return;
  }

  if (!/^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(email)) {
    if (messageBox) {
      messageBox.textContent = 'Please enter a valid email address';
      messageBox.className = 'form-message-inline error';
    }
    return;
  }

  if (password.length < 8 || !/[A-Za-z]/.test(password) || !/\d/.test(password)) {
    if (messageBox) {
      messageBox.textContent = 'Password must be 8+ chars and contain a letter and a digit';
      messageBox.className = 'form-message-inline error';
    }
    return;
  }

  if (password !== confirmPassword) {
    if (messageBox) {
      messageBox.textContent = 'Passwords do not match';
      messageBox.className = 'form-message-inline error';
    }
    return;
  }

  try {
    const response = await fetch(`${API_BASE_URL}/auth/signup`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ username, email, password, turnstile_token: turnstileToken || null })
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      if (messageBox) {
        messageBox.textContent = data.detail || 'Signup failed';
        messageBox.className = 'form-message-inline error';
      }
      if (window.turnstile) {
        try { window.turnstile.reset(); } catch (e) {}
      }
      return;
    }

    currentUser = data;
    localStorage.setItem('token', data.access_token);
    localStorage.setItem('user', JSON.stringify(data));
    setUserDisplayState();

    if (messageBox) {
      messageBox.textContent = 'Account created successfully';
      messageBox.className = 'form-message-inline success';
    }

    showToast('🎉 Account created successfully', 'success');
    window.location.href = 'dashboard.html';
  } catch (error) {
    if (messageBox) {
      messageBox.textContent = 'Network error. Please try again.';
      messageBox.className = 'form-message-inline error';
    }
    showToast('❌ Network error', 'error');
  }
}

async function loadChallenges() {
  const feed = safeGetById('challengeFeed');
  const challengesFeed = safeGetById('challengesFeed');
  const targetFeed = feed || challengesFeed;
  if (!targetFeed) return;

  try {
    const response = await fetch(`${API_BASE_URL}/challenges`);
    if (!response.ok) {
      throw new Error('Failed to fetch challenges');
    }

    allChallenges = await response.json();
    filteredChallenges = [...allChallenges];
    renderChallenges();
  } catch (error) {
    console.error('Error loading challenges:', error);
    if (targetFeed) {
      targetFeed.innerHTML = '<div class="loading">Unable to load challenges</div>';
    }
  }
}

function renderCommunityChallenges() {
  const container = safeGetById('communityFeed');
  if (!container) return;

  const solvedSet = new Set(Array.isArray(currentUser?.solved_challenges) ? currentUser.solved_challenges : []);
  const visibleChallenges = communityChallenges.filter((c) => !solvedSet.has(c.id));

  const sortedChallenges = [...visibleChallenges].sort((a, b) => {
    if (communitySortMode === 'popular') return Number(b.solved_count || 0) - Number(a.solved_count || 0);
    if (communitySortMode === 'reward') return Number(b.points_reward || 0) - Number(a.points_reward || 0);
    return new Date(b.created_at || 0) - new Date(a.created_at || 0);
  });

  if (!sortedChallenges.length) {
    container.innerHTML = '<div class="loading">No new community challenges yet. You\'ve solved everything that\'s available!</div>';
    return;
  }

  container.innerHTML = sortedChallenges.map((challenge) => `
    <article class="challenge-card community-card">
      <div class="card-inner">
        <div class="card-header-bar">
          <div class="card-meta-left">
            <div class="card-category-icon"><i class="fa-solid fa-users"></i></div>
            <span class="card-category-name">r/${escapeHtml(challenge.category || 'Community')}</span>
            <span class="card-time-ago">• ${challenge.created_at ? new Date(challenge.created_at).toLocaleDateString() : 'Today'}</span>
            <span class="card-category-badge">${escapeHtml(challenge.difficulty || 'Open')}</span>
          </div>
          <div class="card-meta-right">
            <a class="card-joined-pill" href="challenge_detail.html?id=${challenge.id}">
              <i class="fa-solid fa-play"></i> Start
            </a>
            <div class="challenge-options-dropdown">
              <button class="card-options-btn" type="button" aria-label="More options" onclick="toggleOptionsMenu(event)">
                <i class="fa-solid fa-ellipsis"></i>
              </button>
              <div class="dropdown-menu">
                <button class="dropdown-item" onclick="shareChallenge(${challenge.id})">
                  <i class="fa-solid fa-share"></i> Share
                </button>
                <button class="dropdown-item" onclick="reportChallenge(${challenge.id})">
                  <i class="fa-solid fa-flag"></i> Report
                </button>
                ${currentUser && Number(challenge.created_by) === Number(currentUser.id) ? `<button class="dropdown-item dropdown-danger" onclick="removeChallenge(${challenge.id})">
                  <i class="fa-solid fa-trash"></i> Delete
                </button>` : ''}
              </div>
            </div>
          </div>
        </div>

        <div class="challenge-title">${escapeHtml(challenge.title)}</div>

        <div class="challenge-media">
          ${renderMedia(challenge.telegram_file_id)}
        </div>

        <div class="challenge-description">
          ${escapeHtml((challenge.description || '').substring(0, 180))}...
        </div>

        <div class="card-action-bar">
          <button class="vote-pill" type="button">
            <span class="vote-arrow"><i class="fa-solid fa-arrow-up"></i></span>
            <span class="vote-count">${challenge.points_reward || 100}</span>
            <span class="vote-arrow"><i class="fa-solid fa-arrow-down"></i></span>
          </button>
          <a class="action-pill" href="comments.html?id=${challenge.id}">
            <i class="fa-solid fa-comment"></i> <span class="comment-count" data-challenge-id="${challenge.id}">${Number(challenge.comments_count || 0)}</span> Comments
          </a>
          <a class="action-pill" href="challenge_detail.html?id=${challenge.id}">
            <i class="fa-solid fa-flag"></i> Solve
          </a>
        </div>
      </div>
    </article>
  `).join('');

}

async function loadCommunityChallenges() {
  const container = safeGetById('communityFeed');
  if (!container) return;

  try {
    const response = await fetch(`${API_BASE_URL}/challenges/community`);
    if (!response.ok) {
      throw new Error('Failed to fetch community challenges');
    }

    communityChallenges = await response.json();
    renderCommunityChallenges();
  } catch (error) {
    console.error('Error loading community challenges:', error);
    container.innerHTML = '<div class="loading">Unable to load community board</div>';
  }
}

async function loadModerationQueue() {
  const container = safeGetById('moderationQueue');
  if (!container) return;

  try {
    const token = localStorage.getItem('token');
    if (!token) return;

    const response = await fetch(`${API_BASE_URL}/moderation/reports`, {
      headers: { Authorization: `Bearer ${token}` }
    });

    if (!response.ok) {
      throw new Error('Moderation queue load failed');
    }

    const reports = await response.json();
    if (!reports.length) {
      container.innerHTML = '<div class="loading-small">No open moderation reports</div>';
      return;
    }

    container.innerHTML = reports.map((report) => `
      <div class="report-item">
        <div class="report-head">
          <strong>${escapeHtml(report.challenge_title)}</strong>
          <span>${escapeHtml(report.reason)}</span>
        </div>
        <div class="report-meta">Reported by ${escapeHtml(report.reporter)}</div>
        <div class="report-actions">
          <button type="button" class="mini-btn success" data-action="approve" data-report-id="${report.id}">Approve</button>
          <button type="button" class="mini-btn danger" data-action="reject" data-report-id="${report.id}">Reject</button>
          <button type="button" class="mini-btn warn" data-action="ban" data-report-id="${report.id}">Ban</button>
        </div>
      </div>
    `).join('');

    container.querySelectorAll('.mini-btn').forEach((button) => {
      button.addEventListener('click', async () => {
        const action = button.dataset.action;
        const reportId = Number(button.dataset.reportId);
        if (!reportId || !action) return;
        await handleModerationAction(reportId, action);
      });
    });
  } catch (error) {
    console.error('Error loading moderation queue:', error);
    container.innerHTML = '<div class="loading-small">Moderation queue unavailable</div>';
  }
}

async function handleModerationAction(reportId, action) {
  const token = localStorage.getItem('token');
  if (!token) {
    showToast('⚠️ Session expired', 'error');
    return;
  }

  try {
    const response = await fetch(`${API_BASE_URL}/moderation/reports/${reportId}/resolve`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify({ action, reason: `Moderation action: ${action}` })
    });

    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data.detail || 'Moderation action failed');
    }

    showToast(`✅ Report ${action}d`, 'success');
    await loadModerationQueue();
  } catch (error) {
    console.error('Error resolving moderation action:', error);
    showToast('❌ Moderation action failed', 'error');
  }
}

async function reportChallenge(challengeId, context = 'challenge') {
  console.log('[REPORT] Opening report modal for challenge:', challengeId);
  const token = localStorage.getItem('token');
  if (!token) {
    showToast('⚠️ Please sign in to report a challenge', 'error');
    return;
  }

  reportChallengeId = challengeId;
  reportContext = context;
  reportCommentId = null;
  selectedReportReason = null;
  const submitBtn = safeGetById('submitReportBtn');
  if (submitBtn) submitBtn.disabled = true;

  const reasonsContainer = safeGetById('reportReasons');
  if (reasonsContainer) {
    reasonsContainer.innerHTML = REPORT_REASONS.map(reason => `
      <div class="report-reason-card" data-reason="${reason.id}" onclick="selectReportReason('${reason.id}')">
        <input type="radio" name="reportReason" id="reason-${reason.id}" value="${reason.id}">
        <label for="reason-${reason.id}">
          <div style="font-weight:700;">${reason.label}</div>
          <div style="font-size:0.8rem;color:var(--muted);font-weight:400;">${reason.description}</div>
        </label>
      </div>
    `).join('');
  }

  const modal = safeGetById('reportModal');
  if (modal) {
    modal.classList.add('active');
  } else {
    console.error('[REPORT] Modal element not found');
  }
}

function selectReportReason(reasonId) {
  selectedReportReason = reasonId;
  const submitBtn = safeGetById('submitReportBtn');
  if (submitBtn) submitBtn.disabled = false;

  document.querySelectorAll('.report-reason-card').forEach(card => {
    card.classList.toggle('selected', card.dataset.reason === reasonId);
  });

  const radio = document.querySelector(`input[name="reportReason"][value="${reasonId}"]`);
  if (radio) radio.checked = true;
}

async function submitReport() {
  console.log('[REPORT] Submitting report:', { challengeId: reportChallengeId, reason: selectedReportReason });
  if (!selectedReportReason || !reportChallengeId) {
    console.error('[REPORT] Missing data:', { challengeId: reportChallengeId, reason: selectedReportReason });
    return;
  }

  const token = localStorage.getItem('token');
  if (!token) {
    showToast('⚠️ Session expired', 'error');
    return;
  }

  const reasonLabel = REPORT_REASONS.find(r => r.id === selectedReportReason)?.label || selectedReportReason;
  const submitBtn = safeGetById('submitReportBtn');
  if (submitBtn) submitBtn.disabled = true;

  try {
    console.log('[REPORT] Sending API request...');
    const response = await fetch(`${API_BASE_URL}/challenges/${reportChallengeId}/report`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
       body: JSON.stringify({
         reason: reasonLabel,
         details: reportContext === 'comment'
           ? `Comment #${reportCommentId} reported for moderation review`
           : 'Community moderation review requested',
         comment_id: reportContext === 'comment' ? reportCommentId : null
       })
    });

    const data = await response.json().catch(() => ({}));
    console.log('[REPORT] API response:', response.status, data);

    if (!response.ok) {
      throw new Error(data.detail || 'Report failed');
    }

    showToast(
      reportContext === 'comment'
        ? '✅ Comment reported to moderators'
        : '✅ Challenge reported to moderators',
      'success'
    );
    closeReportModal();
  } catch (error) {
    console.error('[REPORT] Error:', error);
    showToast('❌ Unable to report challenge', 'error');
    if (submitBtn) submitBtn.disabled = false;
  }
}

function closeReportModal() {
  const modal = safeGetById('reportModal');
  if (modal) modal.classList.remove('active');
  reportChallengeId = null;
  selectedReportReason = null;
  reportContext = 'challenge';
  reportCommentId = null;
}

let editChallengeId = null;

async function openEditModal(challengeId) {
  console.log('[EDIT] Opening edit modal for challenge:', challengeId);
  const token = localStorage.getItem('token');
  if (!token) {
    showToast('⚠️ Please sign in to edit', 'error');
    return;
  }

  try {
    const response = await fetch(`${API_BASE_URL}/challenges/${challengeId}`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!response.ok) {
      throw new Error('Challenge not found');
    }
    const challenge = await response.json();
    console.log('[EDIT] Challenge data:', challenge);

    editChallengeId = challengeId;
    const container = safeGetById('editDetails');
    if (!container) return;

    container.innerHTML = `
      <form id="editChallengeForm" class="community-form">
        <div class="form-header">
          <div>
            <span class="eyebrow">Edit</span>
            <h3>Update Challenge</h3>
          </div>
        </div>
        <div class="field-grid">
          <label>
            <span>Title</span>
            <input type="text" id="editTitle" value="${escapeHtml(challenge.title || '')}" required>
          </label>
          <label>
            <span>Category</span>
            <input type="text" value="${escapeHtml(challenge.category || '')}" disabled>
          </label>
        </div>
        <label>
          <span>Description</span>
          <textarea id="editDescription" rows="4" required>${escapeHtml(challenge.description || '')}</textarea>
        </label>
        <div class="field-grid">
          <label>
            <span>Hint 1</span>
            <textarea id="editHint1" rows="2">${escapeHtml(challenge.hint_1 || '')}</textarea>
          </label>
          <label>
            <span>Hint 2</span>
            <textarea id="editHint2" rows="2">${escapeHtml(challenge.hint_2 || '')}</textarea>
          </label>
        </div>
        <div class="field-grid">
          <label>
            <span>Hint 1 Cost (coins)</span>
            <input type="number" id="editHint1Cost" value="${challenge.hint_1_cost || 10}" min="0">
          </label>
          <label>
            <span>Hint 2 Cost (coins)</span>
            <input type="number" id="editHint2Cost" value="${challenge.hint_2_cost || 20}" min="0">
          </label>
        </div>
        <div class="field-grid">
          <label>
            <span>Reward Coins</span>
            <input type="number" id="editReward" value="${challenge.points_reward || 100}" min="0">
          </label>
          <label>
            <span>Tags</span>
            <input type="text" id="editTags" value="${escapeHtml(challenge.tags || '')}">
          </label>
        </div>
        <button type="submit" class="btn btn-primary btn-block">Save Changes</button>
      </form>
    `;

    const form = safeGetById('editChallengeForm');
    if (form) {
      form.addEventListener('submit', submitEditChallenge);
    } else {
      console.error('[EDIT] Form not found');
    }

    const modal = safeGetById('editModal');
    if (modal) {
      modal.classList.add('active');
      console.log('[EDIT] Modal opened');
    } else {
      console.error('[EDIT] Modal not found');
    }
  } catch (error) {
    console.error('[EDIT] Error loading challenge for edit:', error);
    showToast('❌ Unable to load challenge', 'error');
  }
}

async function submitEditChallenge(event) {
  event.preventDefault();
  console.log('[EDIT] Submitting edit for challenge:', editChallengeId);
  if (!editChallengeId) {
    console.error('[EDIT] No challenge ID');
    return;
  }

  const token = localStorage.getItem('token');
  if (!token) {
    showToast('⚠️ Session expired', 'error');
    return;
  }

  const payload = {
    title: safeGetById('editTitle')?.value,
    description: safeGetById('editDescription')?.value,
    hint_1: safeGetById('editHint1')?.value,
    hint_2: safeGetById('editHint2')?.value,
    hint_1_cost: Number(safeGetById('editHint1Cost')?.value || 0),
    hint_2_cost: Number(safeGetById('editHint2Cost')?.value || 0),
    points_reward: Number(safeGetById('editReward')?.value || 0),
    tags: safeGetById('editTags')?.value,
  };
  console.log('[EDIT] Payload:', payload);

  try {
    const response = await fetch(`${API_BASE_URL}/challenges/${editChallengeId}`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify(payload)
    });

    const data = await response.json().catch(() => ({}));
    console.log('[EDIT] Response:', response.status, data);
    if (!response.ok) {
      throw new Error(data.detail || 'Update failed');
    }

    showToast('✅ Challenge updated successfully', 'success');
    closeEditModal();
    await loadChallenges();
    await loadCommunityChallenges();
    await loadProfile();
  } catch (error) {
    console.error('[EDIT] Error updating challenge:', error);
    showToast('❌ Unable to update challenge', 'error');
  }
}

function closeEditModal() {
  const modal = safeGetById('editModal');
  if (modal) modal.classList.remove('active');
  editChallengeId = null;
}

function openProfileEditModal() {
  if (!currentUser) return;

  const container = safeGetById('editDetails');
  if (!container) return;

  container.innerHTML = `
    <form id="profileEditForm" class="community-form">
      <div class="form-header">
        <div>
          <span class="eyebrow">Edit</span>
          <h3>Update Profile</h3>
        </div>
      </div>
      <div class="field-grid">
        <label>
          <span>Username</span>
          <input type="text" id="editProfileUsername" value="${escapeHtml(currentUser.username || '')}" required>
        </label>
        <label>
          <span>Avatar URL</span>
          <input type="url" id="editProfileAvatar" value="${escapeHtml(currentUser.avatar_url || '')}" placeholder="https://example.com/avatar.jpg">
        </label>
      </div>
      <label>
        <span>Bio</span>
        <textarea id="editProfileBio" rows="3" placeholder="Tell us about yourself...">${escapeHtml(currentUser.bio || '')}</textarea>
      </label>
      <button type="submit" class="btn btn-primary btn-block">Save Changes</button>
    </form>
  `;

  const form = safeGetById('profileEditForm');
  if (form) {
    form.addEventListener('submit', submitProfileEdit);
  }

  const modal = safeGetById('editModal');
  if (modal) modal.classList.add('active');
}

async function submitProfileEdit(event) {
  event.preventDefault();

  const token = localStorage.getItem('token');
  if (!token) {
    showToast('⚠️ Session expired', 'error');
    return;
  }

  const payload = {
    username: safeGetById('editProfileUsername')?.value,
    bio: safeGetById('editProfileBio')?.value,
    avatar_url: safeGetById('editProfileAvatar')?.value || null
  };

  try {
    const response = await fetch(`${API_BASE_URL}/profile`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify(payload)
    });

    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data.detail || 'Update failed');
    }

    currentUser = { ...currentUser, ...data };
    localStorage.setItem('user', JSON.stringify(currentUser));
    setUserDisplayState();

    showToast('✅ Profile updated successfully', 'success');
    closeEditModal();
    await loadProfile();
  } catch (error) {
    console.error('Error updating profile:', error);
    showToast('❌ Unable to update profile', 'error');
  }
}

function setupTelegramConnect() {
  const connectBtn = safeGetById('connectTelegramBtn');
  if (connectBtn) {
    connectBtn.addEventListener('click', async () => {
      const token = localStorage.getItem('token');
      if (!token) {
        showToast('⚠️ Please sign in', 'error');
        return;
      }
      try {
        const nonceResponse = await fetch(`${API_BASE_URL}/settings/telegram/connect-nonce`, {
          headers: { Authorization: `Bearer ${token}` }
        });
        if (!nonceResponse.ok) {
          showToast('❌ Unable to start Telegram connection', 'error');
          return;
        }
        const nonceData = await nonceResponse.json();
        const nonce = nonceData.nonce;

        const botInfoResponse = await fetch(`${API_BASE_URL}/settings/telegram/bot-info`);
        const botInfo = await botInfoResponse.json();
        if (!botInfo.configured || !botInfo.bot_username) {
          showToast('⚠️ Telegram bot not configured', 'error');
          return;
        }
        const deepLink = `https://t.me/${botInfo.bot_username}?start=connect_${currentUser.id}_${nonce}`;
        window.open(deepLink, '_blank');
        showToast('📨 Open Telegram and send /start to connect', 'success');
      } catch (error) {
        showToast('❌ Unable to start Telegram connection', 'error');
      }
    });
  }

  const disconnectBtn = safeGetById('disconnectTelegramBtn');
  if (disconnectBtn) {
    disconnectBtn.addEventListener('click', async () => {
      const token = localStorage.getItem('token');
      if (!token) return;
      if (!confirm('Disconnect Telegram? You will no longer receive notifications.')) return;
      try {
        const response = await fetch(`${API_BASE_URL}/settings/telegram/disconnect`, {
          method: 'DELETE',
          headers: { Authorization: `Bearer ${token}` }
        });
        if (response.ok) {
          showToast('✅ Telegram disconnected', 'success');
          await loadTelegramStatus();
        }
      } catch (error) {
        showToast('❌ Unable to disconnect', 'error');
      }
    });
  }
}

async function loadTelegramStatus() {
  const statusEl = safeGetById('telegramConnectStatus');
  const connectBtn = safeGetById('connectTelegramBtn');
  const disconnectBtn = safeGetById('disconnectTelegramBtn');
  if (!statusEl) return;

  if (!currentUser || !currentUser.telegram_chat_id) {
    statusEl.className = 'telegram-status';
    statusEl.innerHTML = '<div class="status-row"><i class="fa-brands fa-telegram"></i> Not connected — connect Telegram to receive security alerts and password reset links.</div>';
    if (connectBtn) connectBtn.style.display = 'block';
    if (disconnectBtn) disconnectBtn.style.display = 'none';
    return;
  }

  statusEl.className = 'telegram-status connected';
  statusEl.innerHTML = `<div class="status-row"><i class="fa-solid fa-circle-check"></i> Connected to Telegram</div><div style="font-size:0.82rem;margin-top:6px;color:var(--muted);">Chat ID: ${currentUser.telegram_chat_id}</div>`;
  if (connectBtn) connectBtn.style.display = 'none';
  if (disconnectBtn) disconnectBtn.style.display = 'block';
}

let _telegramPollInterval = null;

function startTelegramConnectionPolling() {
  if (_telegramPollInterval) return;
  if (!currentUser) return;
  if (currentUser.telegram_chat_id) return;

  _telegramPollInterval = setInterval(async () => {
    const token = localStorage.getItem('token');
    if (!token) {
      stopTelegramConnectionPolling();
      return;
    }
    try {
      const response = await fetch(`${API_BASE_URL}/profile`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (!response.ok) return;
      const profile = await response.json();
      if (profile.telegram_chat_id) {
        currentUser.telegram_chat_id = profile.telegram_chat_id;
        if (profile.telegram_notifications !== undefined) {
          currentUser.telegram_notifications = profile.telegram_notifications;
        }
        localStorage.setItem('user', JSON.stringify(currentUser));
        stopTelegramConnectionPolling();
        showToast('✅ Telegram connected!', 'success');
        await loadTelegramStatus();
      }
    } catch (error) {
      console.error('Polling error:', error);
    }
  }, 4000);

  setTimeout(() => stopTelegramConnectionPolling(), 300000);
}

function stopTelegramConnectionPolling() {
  if (_telegramPollInterval) {
    clearInterval(_telegramPollInterval);
    _telegramPollInterval = null;
  }
}

async function loadSettings() {
  if (!currentUser) return;

  const token = localStorage.getItem('token');
  if (!token) {
    window.location.href = 'login.html';
    return;
  }

  try {
    const response = await fetch(`${API_BASE_URL}/profile`, {
      headers: { Authorization: `Bearer ${token}` }
    });

    if (!response.ok) {
      throw new Error('Failed to load settings');
    }

    const profile = await response.json();
    currentUser = { ...currentUser, ...profile };

    const notifyNewChallenges = safeGetById('notifyNewChallenges');
    const notifyComments = safeGetById('notifyComments');
    const notifyMentions = safeGetById('notifyMentions');
    const hideEmail = safeGetById('hideEmail');
    const publicProfile = safeGetById('publicProfile');

    if (notifyNewChallenges) notifyNewChallenges.checked = profile.notify_new_challenges !== false;
    if (notifyComments) notifyComments.checked = profile.notify_comments !== false;
    if (notifyMentions) notifyMentions.checked = profile.notify_mentions !== false;
    if (hideEmail) hideEmail.checked = profile.hide_email !== false;
    if (publicProfile) publicProfile.checked = profile.public_profile !== false;
  } catch (error) {
    console.error('Error loading settings:', error);
    showToast('❌ Unable to load settings', 'error');
  }
}

function setupSettingsForms() {
  const passwordForm = safeGetById('passwordForm');
  if (passwordForm) {
    passwordForm.addEventListener('submit', submitPasswordChange);
  }

  const notificationsForm = safeGetById('notificationsForm');
  if (notificationsForm) {
    notificationsForm.addEventListener('submit', submitNotificationSettings);
  }

  const privacyForm = safeGetById('privacyForm');
  if (privacyForm) {
    privacyForm.addEventListener('submit', submitPrivacySettings);
  }

  const deleteAccountBtn = safeGetById('deleteAccountBtn');
  if (deleteAccountBtn) {
    deleteAccountBtn.addEventListener('click', confirmDeleteAccount);
  }
}

async function submitPasswordChange(event) {
  event.preventDefault();

  const currentPassword = safeGetById('currentPassword')?.value;
  const newPassword = safeGetById('newPassword')?.value;
  const confirmNewPassword = safeGetById('confirmNewPassword')?.value;
  const messageEl = safeGetById('passwordMessage');

  if (!currentPassword || !newPassword || !confirmNewPassword) {
    if (messageEl) {
      messageEl.textContent = 'Please fill in all password fields';
      messageEl.className = 'form-message show error';
    }
    return;
  }

  if (newPassword !== confirmNewPassword) {
    if (messageEl) {
      messageEl.textContent = 'New passwords do not match';
      messageEl.className = 'form-message show error';
    }
    return;
  }

  if (newPassword.length < 8 || !/[A-Za-z]/.test(newPassword) || !/\d/.test(newPassword)) {
    if (messageEl) {
      messageEl.textContent = 'Password must be 8+ chars and contain a letter and a digit';
      messageEl.className = 'form-message show error';
    }
    return;
  }

  if (newPassword === currentPassword) {
    if (messageEl) {
      messageEl.textContent = 'New password must be different from the current one';
      messageEl.className = 'form-message show error';
    }
    return;
  }

  const token = localStorage.getItem('token');
  if (!token) {
    showToast('⚠️ Session expired', 'error');
    return;
  }

  try {
    const response = await fetch(`${API_BASE_URL}/settings/password`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify({
        current_password: currentPassword,
        new_password: newPassword
      })
    });

    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data.detail || 'Password update failed');
    }

    if (messageEl) {
      messageEl.textContent = 'Password updated successfully';
      messageEl.className = 'form-message show success';
    }

    safeGetById('passwordForm').reset();
    showToast('✅ Password updated successfully', 'success');
  } catch (error) {
    console.error('Error updating password:', error);
    if (messageEl) {
      messageEl.textContent = error.message || 'Unable to update password';
      messageEl.className = 'form-message show error';
    }
    showToast('❌ Unable to update password', 'error');
  }
}

async function submitNotificationSettings(event) {
  event.preventDefault();

  const token = localStorage.getItem('token');
  if (!token) {
    showToast('⚠️ Session expired', 'error');
    return;
  }

  const payload = {
    notify_new_challenges: safeGetById('notifyNewChallenges')?.checked ?? true,
    notify_comments: safeGetById('notifyComments')?.checked ?? true,
    notify_mentions: safeGetById('notifyMentions')?.checked ?? true
  };

  try {
    const response = await fetch(`${API_BASE_URL}/settings/notifications`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify(payload)
    });

    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data.detail || 'Update failed');
    }

    currentUser = { ...currentUser, ...data };
    localStorage.setItem('user', JSON.stringify(currentUser));

    const messageEl = safeGetById('notificationsMessage');
    if (messageEl) {
      messageEl.textContent = 'Notification preferences saved';
      messageEl.className = 'form-message show success';
    }
    showToast('✅ Notification preferences saved', 'success');
  } catch (error) {
    console.error('Error updating notifications:', error);
    const messageEl = safeGetById('notificationsMessage');
    if (messageEl) {
      messageEl.textContent = error.message || 'Unable to save preferences';
      messageEl.className = 'form-message show error';
    }
    showToast('❌ Unable to save preferences', 'error');
  }
}

async function submitPrivacySettings(event) {
  event.preventDefault();

  const token = localStorage.getItem('token');
  if (!token) {
    showToast('⚠️ Session expired', 'error');
    return;
  }

  const payload = {
    hide_email: safeGetById('hideEmail')?.checked ?? true,
    public_profile: safeGetById('publicProfile')?.checked ?? true
  };

  try {
    const response = await fetch(`${API_BASE_URL}/settings/privacy`, {
      method: 'PUT',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify(payload)
    });

    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data.detail || 'Update failed');
    }

    currentUser = { ...currentUser, ...data };
    localStorage.setItem('user', JSON.stringify(currentUser));

    const messageEl = safeGetById('privacyMessage');
    if (messageEl) {
      messageEl.textContent = 'Privacy settings saved';
      messageEl.className = 'form-message show success';
    }
    showToast('✅ Privacy settings saved', 'success');
  } catch (error) {
    console.error('Error updating privacy settings:', error);
    const messageEl = safeGetById('privacyMessage');
    if (messageEl) {
      messageEl.textContent = error.message || 'Unable to save settings';
      messageEl.className = 'form-message show error';
    }
    showToast('❌ Unable to save settings', 'error');
  }
}

function confirmDeleteAccount() {
  const message = safeGetById('confirmMessage');
  if (message) {
    message.textContent = 'This will permanently delete your account, all progress, badges, and created challenges. This action cannot be undone.';
  }
  const modal = safeGetById('confirmModal');
  if (modal) modal.classList.add('active');
}

async function deleteAccount() {
  const token = localStorage.getItem('token');
  if (!token) {
    showToast('⚠️ Session expired', 'error');
    return;
  }

  try {
    const response = await fetch(`${API_BASE_URL}/settings/account`, {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` }
    });

    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data.detail || 'Delete failed');
    }

    localStorage.removeItem('token');
    localStorage.removeItem('user');
    currentUser = null;

    showToast('✅ Account deleted', 'success');
    setTimeout(() => {
      window.location.href = 'index.html';
    }, 1500);
  } catch (error) {
    console.error('Error deleting account:', error);
    showToast('❌ Unable to delete account', 'error');
  }
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text || '';
  return div.innerHTML;
}

function shareChallenge(challengeId) {
  const url = `${window.location.origin}${window.location.pathname.replace('index.html', '')}challenge_detail.html?id=${challengeId}`;
  if (navigator.clipboard) {
    navigator.clipboard.writeText(url).then(() => {
      showToast('🔗 Challenge link copied to clipboard', 'success');
    }).catch(() => {
      showToast('🔗 Share: ' + url, 'success');
    });
  } else {
    showToast('🔗 Share: ' + url, 'success');
  }
}

function hintQuick(challengeId) {
  openChallengeModal(challengeId);
}

async function renderTopChallenges() {
  const container = safeGetById('topChallengesList');
  if (!container) return;

  try {
    const response = await fetch(`${API_BASE_URL}/challenges?limit=5`);
    if (!response.ok) throw new Error('Failed to load top challenges');
    const challenges = await response.json();

    if (!challenges.length) {
      container.innerHTML = '<div class="loading-small">No challenges yet</div>';
      return;
    }

    container.innerHTML = challenges.slice(0, 5).map((challenge) => `
      <div class="sidebar-item" onclick="openChallengeModal(${challenge.id})">
        <div class="sidebar-item-thumb">
          ${challenge.telegram_file_id ? `<img src="/api/media/${encodeURIComponent(challenge.telegram_file_id)}" alt="" loading="lazy" onerror="this.style.display='none';this.parentElement.innerHTML='<i class=\\'fa-solid fa-image\\' style=\\'color:#8b949e;font-size:1.2rem;\\'></i>';" style="width:100%;height:100%;object-fit:cover;border-radius:8px;">` : '<i class="fa-solid fa-image" style="color:#8b949e;font-size:1.2rem;"></i>'}
        </div>
        <div class="sidebar-item-body">
          <div class="sidebar-item-title">${escapeHtml(challenge.title)}</div>
          <div class="sidebar-item-meta">
            <i class="fa-solid fa-coins"></i> ${challenge.points_reward} • <i class="fa-solid fa-check"></i> ${challenge.solved_count || 0}
          </div>
        </div>
      </div>
    `).join('');
  } catch (error) {
    console.error('Error loading top challenges:', error);
    container.innerHTML = '<div class="loading-small">Unable to load top challenges</div>';
  }
}

async function renderRecentActivity() {
  const container = safeGetById('recentActivityList');
  if (!container) return;

  try {
    const token = localStorage.getItem('token');
    if (!token) {
      container.innerHTML = '<div class="loading-small">Sign in to see activity</div>';
      return;
    }

    const response = await fetch(`${API_BASE_URL}/profile`, {
      headers: { Authorization: `Bearer ${token}` }
    });
    if (!response.ok) throw new Error('Failed to load profile');
    const profile = await response.json();

    const history = Array.isArray(profile.history) ? profile.history.slice(0, 5) : [];

    if (!history.length) {
      container.innerHTML = '<div class="loading-small">No recent activity yet</div>';
      return;
    }

    container.innerHTML = history.map((item) => `
      <div class="sidebar-item">
        <div class="sidebar-item-thumb">
          ${item.thumbnail ? `<img src="${item.thumbnail}" alt="" style="width:100%;height:100%;object-fit:cover;border-radius:8px;">` : '<i class="fa-solid fa-flag-checkered" style="color:#8b949e;font-size:1.2rem;"></i>'}
        </div>
        <div class="sidebar-item-body">
          <div class="sidebar-item-title">${escapeHtml(item.title || 'Solved Challenge')}</div>
          <div class="sidebar-item-meta">${item.date || 'Recently'}</div>
        </div>
      </div>
    `).join('');
  } catch (error) {
    console.error('Error loading recent activity:', error);
    container.innerHTML = '<div class="loading-small">Unable to load activity</div>';
  }
}

function renderMedia(fileId) {
  if (!fileId) {
    return '<span class="media-placeholder"><i class="fa-solid fa-image"></i><span>Media unavailable</span></span>';
  }
  const mediaUrl = `/api/media/${encodeURIComponent(fileId)}`;
  const safeId = encodeURIComponent(fileId);
  const downloadHref = `/api/media/${safeId}?download=1`;
  const downloadBtn = `<a class="media-download-btn" href="${downloadHref}" download title="Download to inspect metadata locally"><i class="fa-solid fa-download"></i><span>Download</span></a>`;
  // All uploads now go through sendDocument to preserve EXIF/metadata,
  // so file_id prefix is no longer a reliable video hint. We render an
  // <img> first; if it's actually a video, handleMediaError swaps in a
  // <video> element via the onerror fallback chain.
  return `<div class="media-wrapper"><img src="${mediaUrl}" alt="Challenge media" loading="lazy" onerror="handleMediaError(this)"/>${downloadBtn}</div>`;
}

function handleMediaError(element) {
  if (!element || element.dataset.mediaFallbackAttempted === 'true') {
    if (element) {
      element.style.display = 'none';
      element.parentElement.innerHTML = '<span class="media-placeholder"><i class="fa-solid fa-broken-image"></i><span>Media unavailable</span></span>';
    }
    return;
  }

  element.dataset.mediaFallbackAttempted = 'true';
  const fallback = element.tagName === 'VIDEO'
    ? document.createElement('img')
    : document.createElement('video');
  fallback.src = element.currentSrc || element.src;
  fallback.dataset.mediaFallbackAttempted = 'true';
  fallback.onerror = () => {
    fallback.style.display = 'none';
    fallback.parentElement.innerHTML = '<span class="media-placeholder"><i class="fa-solid fa-broken-image"></i><span>Media unavailable</span></span>';
  };

  if (fallback.tagName === 'VIDEO') {
    fallback.controls = true;
    fallback.preload = 'metadata';
  } else {
    fallback.alt = 'Challenge media';
    fallback.loading = 'lazy';
  }
  element.replaceWith(fallback);
}

let pendingDeleteChallengeId = null;

function openConfirmDeleteModal(challengeId) {
  pendingDeleteChallengeId = challengeId;
  const message = safeGetById('confirmMessage');
  if (message) {
    message.textContent = 'Are you sure you want to remove this challenge from the board? This action cannot be undone.';
  }
  const modal = safeGetById('confirmModal');
  if (modal) modal.classList.add('active');
}

function closeConfirmDeleteModal() {
  const modal = safeGetById('confirmModal');
  if (modal) modal.classList.remove('active');
  pendingDeleteChallengeId = null;
}

async function performChallengeDelete() {
  const challengeId = pendingDeleteChallengeId;
  if (!challengeId) return;

  const token = localStorage.getItem('token');
  if (!token) {
    showToast('⚠️ Session expired', 'error');
    closeConfirmDeleteModal();
    return;
  }

  try {
    const response = await fetch(`${API_BASE_URL}/challenges/${challengeId}`, {
      method: 'DELETE',
      headers: {
        Authorization: `Bearer ${token}`
      }
    });

    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data.detail || 'Challenge removal failed');
    }

    showToast('✅ Challenge removed', 'success');
    await loadChallenges();
    await loadCommunityChallenges();
  } catch (error) {
    console.error('Error removing challenge:', error);
    showToast('❌ Unable to remove challenge', 'error');
  } finally {
    closeConfirmDeleteModal();
  }
}

function removeChallenge(challengeId) {
  openConfirmDeleteModal(challengeId);
}

async function uploadMediaFile(file) {
  const token = localStorage.getItem('token');
  if (!token) {
    showToast('⚠️ Please sign in', 'error');
    return null;
  }

  if (!file) {
    showToast('❌ No file selected', 'error');
    return null;
  }

  const statusDiv = safeGetById('mediaUploadStatus');
  const progressBar = safeGetById('mediaUploadProgress');
  const statusText = safeGetById('mediaUploadText');

  if (statusDiv) statusDiv.style.display = 'block';
  if (statusText) statusText.textContent = 'Uploading...';

  try {
    const formData = new FormData();
    formData.append('file', file);

    const xhr = new XMLHttpRequest();

    // Progress update
    if (progressBar) {
      xhr.upload.addEventListener('progress', (e) => {
        if (e.lengthComputable) {
          const percentComplete = (e.loaded / e.total) * 100;
          if (progressBar) progressBar.style.width = percentComplete + '%';
          if (statusText) statusText.textContent = `Uploading: ${Math.round(percentComplete)}%`;
        }
      });
    }

    return new Promise((resolve, reject) => {
      xhr.addEventListener('load', () => {
        if (xhr.status === 200) {
          const response = JSON.parse(xhr.responseText);
          if (statusText) statusText.textContent = '✅ Upload complete!';
          if (progressBar) progressBar.style.width = '100%';
          setTimeout(() => {
            if (statusDiv) statusDiv.style.display = 'none';
          }, 1500);
          resolve(response.file_id);
        } else {
          const error = JSON.parse(xhr.responseText);
          if (statusText) statusText.textContent = `❌ ${error.detail || 'Upload failed'}`;
          reject(new Error(error.detail || 'Upload failed'));
        }
      });

      xhr.addEventListener('error', () => {
        if (statusText) statusText.textContent = '❌ Network error';
        reject(new Error('Network error'));
      });

      xhr.open('POST', `${API_BASE_URL}/upload/media`);
      xhr.setRequestHeader('Authorization', `Bearer ${token}`);
      xhr.send(formData);
    });
  } catch (error) {
    console.error('Error uploading media:', error);
    if (statusText) statusText.textContent = `❌ ${error.message}`;
    showToast(`❌ Upload failed: ${error.message}`, 'error');
    return null;
  }
}

async function handleCommunityMediaChange(event) {
  const file = event.target.files?.[0];
  if (!file) return;

  // The previous telegram_file_id (if any) refers to a file the user
  // has now replaced, so clear it immediately. This prevents the user
  // from submitting a challenge with a hidden file_id that points to
  // a stale (or never-uploaded) Telegram file.
  safeSetValue('communityFileId', '');

  // Validate file type
  const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'video/mp4', 'video/webm', 'video/quicktime'];
  if (!allowedTypes.includes(file.type)) {
    showToast('❌ Unsupported file type', 'error');
    event.target.value = '';
    return;
  }

  // Validate file size
  const maxSize = file.type.startsWith('video') ? 50 * 1024 * 1024 : 10 * 1024 * 1024;
  if (file.size > maxSize) {
    showToast(`❌ File too large (max ${Math.round(maxSize / (1024 * 1024))}MB)`, 'error');
    event.target.value = '';
    return;
  }

  // Validate non-empty (browser may give 0-byte files in edge cases)
  if (file.size === 0) {
    showToast('❌ File is empty', 'error');
    event.target.value = '';
    return;
  }

  // Upload file
  const fileId = await uploadMediaFile(file);
  if (fileId) {
    safeSetValue('communityFileId', fileId);
    showToast('✅ Media uploaded successfully', 'success');
  } else {
    // Upload failed — make sure the hidden id is empty so the form
    // can't be submitted with a missing media reference.
    safeSetValue('communityFileId', '');
  }
}

async function handleCommunityChallengeSubmit(event) {
  event.preventDefault();

  const token = localStorage.getItem('token');
  if (!token) {
    showToast('⚠️ Please sign in to publish a challenge', 'error');
    window.location.href = 'login.html';
    return;
  }

  const form = event.currentTarget;
  const formData = new FormData(form);
  const body = {
    title: formData.get('title')?.toString().trim(),
    category: formData.get('category')?.toString().trim(),
    difficulty: formData.get('difficulty')?.toString() || 'Easy',
    description: formData.get('description')?.toString().trim(),
    telegram_file_id: formData.get('telegram_file_id')?.toString().trim(),
    correct_flag: formData.get('correct_flag')?.toString().trim(),
    points_reward: Number(formData.get('points_reward') || 100),
    hint_1: formData.get('hint_1')?.toString().trim() || '',
    hint_2: formData.get('hint_2')?.toString().trim() || '',
    disclaimer_accepted: !!formData.get('disclaimer_accepted'),
    tags: formData.get('tags')?.toString().trim() || '',
    solution_walkthrough: formData.get('solution_walkthrough')?.toString() || ''
  };

  const messageBox = safeGetById('communityFormMessage');
  const setFormError = (msg) => {
    if (messageBox) {
      messageBox.textContent = msg;
      messageBox.className = 'form-message show error';
    }
  };

  if (!body.title) {
    setFormError('Challenge title is required.');
    return;
  }
  if (!body.category) {
    setFormError('Category is required.');
    return;
  }
  if (!body.description) {
    setFormError('Description is required.');
    return;
  }
  if (!body.telegram_file_id) {
    setFormError('Please upload media before publishing the challenge.');
    return;
  }
  if (body.telegram_file_id.length < 20 || body.telegram_file_id.length > 256) {
    setFormError('Media reference looks invalid. Please re-upload the file.');
    return;
  }
  if (body.title.length > 120) {
    setFormError('Title must be 120 characters or less.');
    return;
  }
  if (body.description.length > 4000) {
    setFormError('Description must be 4000 characters or less.');
    return;
  }
  if (body.correct_flag.length > 200) {
    setFormError('Flag must be 200 characters or less.');
    return;
  }
  if (!['Easy', 'Medium', 'Hard'].includes(body.difficulty)) {
    setFormError('Difficulty must be Easy, Medium, or Hard.');
    return;
  }
  if (body.points_reward < 10 || body.points_reward > 1000) {
    setFormError('Reward must be between 10 and 1000 coins.');
    return;
  }
  if (body.solution_walkthrough && body.solution_walkthrough.length > 10000) {
    setFormError('Walkthrough must be 10000 characters or less.');
    return;
  }
  if (!body.correct_flag) {
    setFormError('Correct flag is required.');
    return;
  }

  try {
    const response = await fetch(`${API_BASE_URL}/challenges/community/create`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify(body)
    });

    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const errorMsg = data.detail || 'Unable to publish challenge';
      if (messageBox) {
        messageBox.textContent = errorMsg;
        messageBox.className = 'form-message show error';
      }
      if (response.status === 429) {
        showToast('⚠️ Weekly quota reached', 'error');
      } else if (response.status === 400 && /disclaimer|sensitive|identity/i.test(errorMsg)) {
        showToast('❌ Challenge rejected by policy', 'error');
      } else {
        showToast(`❌ ${errorMsg}`, 'error');
      }
      return;
    }

    const quota = data.quota;
    const successMsg = quota
      ? `Published! ${quota.remaining ?? '∞'} of ${quota.limit} weekly CTF(s) remaining.`
      : 'Community challenge published successfully';
    form.reset();
    safeSetValue('communityFileId', '');
    const modal = safeGetById('communityModal');
    if (modal) modal.classList.remove('active');
    if (messageBox) {
      messageBox.textContent = successMsg;
      messageBox.className = 'form-message show success';
    }
    showToast(`✅ ${successMsg}`, 'success');
    await loadCommunityChallenges();
    return;
  } catch (error) {
    console.error('Error publishing community challenge:', error);
    if (messageBox) {
      messageBox.textContent = 'Network error. Please try again.';
      messageBox.className = 'form-message show error';
    }
    showToast('❌ Publish failed', 'error');
  }
}

function renderChallenges() {
  const feed = safeGetById('challengeFeed') || safeGetById('challengesFeed');
  if (!feed) return;

  const solvedSet = new Set(Array.isArray(currentUser?.solved_challenges) ? currentUser.solved_challenges : []);
  const visible = filteredChallenges.filter((c) => !solvedSet.has(c.id));

  if (!visible.length) {
    feed.innerHTML = '<div class="loading">No new challenges available. You\'ve solved everything!</div>';
    return;
  }

  feed.innerHTML = visible.map((challenge) => `
    <article class="challenge-card">
      <div class="card-inner">
        <div class="card-header-bar">
          <div class="card-meta-left">
            <div class="card-category-icon"><i class="fa-solid fa-user-secret"></i></div>
            <span class="card-category-name">r/${escapeHtml(challenge.category || 'OSINT')}</span>
            <span class="card-time-ago">• ${challenge.created_at ? new Date(challenge.created_at).toLocaleDateString() : 'Today'}</span>
            <span class="card-category-badge">${escapeHtml(challenge.difficulty || 'Open')}</span>
            ${challenge.has_walkthrough ? `<span class="walkthrough-pill" title="Author provided a solution walkthrough"><i class="fa-solid fa-lightbulb"></i> Walkthrough</span>` : ''}
          </div>
          <div class="card-meta-right">
            <a class="card-joined-pill" href="challenge_detail.html?id=${challenge.id}">
              <i class="fa-solid fa-play"></i> Start
            </a>
            <div class="challenge-options-dropdown">
              <button class="card-options-btn" type="button" aria-label="More options" onclick="toggleOptionsMenu(event)">
                <i class="fa-solid fa-ellipsis"></i>
              </button>
              <div class="dropdown-menu">
                <button class="dropdown-item" onclick="shareChallenge(${challenge.id})">
                  <i class="fa-solid fa-share"></i> Share
                </button>
                <button class="dropdown-item" onclick="reportChallenge(${challenge.id})">
                  <i class="fa-solid fa-flag"></i> Report
                </button>
                ${currentUser && Number(challenge.created_by) === Number(currentUser.id) ? `<button class="dropdown-item dropdown-danger" onclick="removeChallenge(${challenge.id})">
                  <i class="fa-solid fa-trash"></i> Delete
                </button>` : ''}
              </div>
            </div>
          </div>
        </div>

        <div class="challenge-title">${escapeHtml(challenge.title)}</div>

        <div class="challenge-media">
          ${renderMedia(challenge.telegram_file_id)}
        </div>

        <div class="challenge-description">
          ${escapeHtml((challenge.description || '').substring(0, 180))}...
        </div>

        <div class="card-action-bar">
          <button class="vote-pill" type="button">
            <span class="vote-arrow"><i class="fa-solid fa-arrow-up"></i></span>
            <span class="vote-count">${challenge.points_reward || 100}</span>
            <span class="vote-arrow"><i class="fa-solid fa-arrow-down"></i></span>
          </button>
          <a class="action-pill" href="comments.html?id=${challenge.id}">
            <i class="fa-solid fa-comment"></i> <span class="comment-count" data-challenge-id="${challenge.id}">${Number(challenge.comments_count || 0)}</span> Comments
          </a>
          <a class="action-pill" href="challenge_detail.html?id=${challenge.id}">
            <i class="fa-solid fa-flag"></i> Solve
          </a>
        </div>
      </div>
    </article>
  `).join('');

}

async function loadChallengeDetailPage(challengeId) {
  const loading = safeGetById('detailLoading');
  const errorEl = safeGetById('detailError');
  const content = safeGetById('detailContent');
  const pageTitle = safeGetById('detailPageTitle');

  if (loading) loading.style.display = 'block';
  if (errorEl) errorEl.style.display = 'none';
  if (content) content.style.display = 'none';
  if (pageTitle) pageTitle.textContent = 'Loading...';

  try {
    const response = await fetch(`${API_BASE_URL}/challenges/${challengeId}`);
    if (!response.ok) throw new Error('Challenge lookup failed');
    const challenge = await response.json();

    document.body.dataset.challengeId = challenge.id;

    if (pageTitle) pageTitle.textContent = challenge.title;
    if (safeGetById('detailCategory')) safeGetById('detailCategory').textContent = `r/${escapeHtml(challenge.category || 'OSINT')}`;
    if (safeGetById('detailTime')) safeGetById('detailTime').textContent = `• ${challenge.created_at ? new Date(challenge.created_at).toLocaleDateString() : 'Today'}`;
    if (safeGetById('detailDifficulty')) safeGetById('detailDifficulty').textContent = escapeHtml(challenge.difficulty || 'Open');
    if (safeGetById('detailTitle')) safeGetById('detailTitle').textContent = challenge.title;
    if (safeGetById('detailMedia')) safeGetById('detailMedia').innerHTML = renderMedia(challenge.telegram_file_id ? challenge.telegram_file_id : '');
    if (safeGetById('detailDescription')) safeGetById('detailDescription').textContent = challenge.description || '';
    if (safeGetById('detailReward')) safeGetById('detailReward').textContent = `${challenge.points_reward} Coins`;
    if (safeGetById('detailSolved')) safeGetById('detailSolved').textContent = `${challenge.solved_count || 0} Analysts`;
    if (safeGetById('detailCreated')) safeGetById('detailCreated').textContent = challenge.created_at ? new Date(challenge.created_at).toLocaleDateString() : 'Today';
    if (safeGetById('detailVotes')) safeGetById('detailVotes').textContent = challenge.points_reward || 100;

    // Walkthrough (only rendered for solvers / author / admin)
    const walkthroughEl = safeGetById('detailWalkthrough');
    if (walkthroughEl) {
      if (challenge.can_view_walkthrough && challenge.solution_walkthrough) {
        walkthroughEl.innerHTML = `
          <div class="walkthrough-box">
            <div class="walkthrough-header">
              <i class="fa-solid fa-lightbulb"></i>
              <strong>Solution Walkthrough</strong>
            </div>
            <div class="walkthrough-body">${escapeHtml(challenge.solution_walkthrough)}</div>
          </div>
        `;
        walkthroughEl.style.display = 'block';
      } else {
        walkthroughEl.innerHTML = '';
        walkthroughEl.style.display = 'none';
      }
    }

    const detailHints = safeGetById('detailHints');
    if (detailHints) {
      const hint1 = challenge.has_hint_1;
      const hint2 = challenge.has_hint_2;
      const hint1Cost = challenge.hint_1_cost || 10;
      const hint2Cost = challenge.hint_2_cost || 20;

      let hintHtml = '<div class="hints-container">';
      if (hint1) {
        hintHtml += `<div class="hint-row">
          <div class="hint-info">
            <div class="hint-label">Hint 1</div>
            <div class="hint-cost"><i class="fa-solid fa-coins"></i> ${hint1Cost} coins</div>
          </div>
          <button class="btn btn-light btn-small" type="button" onclick="unlockHint(${challenge.id}, 1)">Unlock</button>
        </div>`;
      }
      if (hint2) {
        hintHtml += `<div class="hint-row">
          <div class="hint-info">
            <div class="hint-label">Hint 2</div>
            <div class="hint-cost"><i class="fa-solid fa-coins"></i> ${hint2Cost} coins</div>
          </div>
          <button class="btn btn-light btn-small" type="button" onclick="unlockHint(${challenge.id}, 2)">Unlock</button>
        </div>`;
      }
      if (!hint1 && !hint2) {
        hintHtml += '<div class="hint-empty">No hints available for this case.</div>';
      }
      hintHtml += '</div>';
      detailHints.innerHTML = hintHtml;
    }

    const deleteBtn = safeGetById('deleteOptionBtn');
    if (deleteBtn) {
      const isCreator = currentUser && Number(challenge.created_by) === Number(currentUser.id);
      deleteBtn.style.display = isCreator ? 'flex' : 'none';
    }

    const commentLink = safeGetById('detailCommentLink');
    if (commentLink) {
      commentLink.href = `comments.html?id=${challenge.id}`;
    }

    const token = localStorage.getItem('token');
    if (token) {
      try {
        const countEl = safeGetById('detailCommentCount');
        if (countEl) countEl.textContent = Number(challenge.comments_count || 0);
      } catch (e) {
        console.error('Error loading comment count:', e);
      }
    }

    if (loading) loading.style.display = 'none';
    if (errorEl) errorEl.style.display = 'none';
    if (content) content.style.display = 'block';
  } catch (error) {
    console.error('Error loading challenge detail page:', error);
    if (loading) loading.style.display = 'none';
    if (errorEl) {
      errorEl.style.display = 'block';
      errorEl.textContent = '❌ Unable to load challenge details';
    }
    if (content) content.style.display = 'none';
  }
}

async function loadCommentsPage(challengeId) {
  const loading = safeGetById('commentsLoading');
  const errorEl = safeGetById('commentsError');
  const content = safeGetById('commentsContent');
  const pageTitle = safeGetById('commentsPageTitle');
  const backBtn = safeGetById('backToChallengeBtn');

  if (loading) loading.style.display = 'block';
  if (errorEl) errorEl.style.display = 'none';
  if (content) content.style.display = 'none';
  if (pageTitle) pageTitle.textContent = 'Loading...';
  if (backBtn) backBtn.href = `challenge_detail.html?id=${challengeId}`;

  try {
    const response = await fetch(`${API_BASE_URL}/challenges/${challengeId}`);
    if (!response.ok) throw new Error('Challenge lookup failed');
    const challenge = await response.json();

    if (pageTitle) pageTitle.textContent = challenge.title;

    await loadComments(challenge.id);

    if (loading) loading.style.display = 'none';
    if (errorEl) errorEl.style.display = 'none';
    if (content) content.style.display = 'block';
  } catch (error) {
    console.error('Error loading comments page:', error);
    if (loading) loading.style.display = 'none';
    if (errorEl) {
      errorEl.style.display = 'block';
      errorEl.textContent = '❌ Unable to load discussion';
    }
    if (content) content.style.display = 'none';
  }
}

function toggleOptionsMenu(event) {
  if (event) event.stopPropagation();
  const dropdown = event ? event.target.closest('.challenge-options-dropdown')?.querySelector('.dropdown-menu') : safeGetById('optionsDropdown');
  if (dropdown) {
    const isOpen = dropdown.style.display === 'block';
    document.querySelectorAll('.dropdown-menu').forEach(m => m.style.display = 'none');
    dropdown.style.display = isOpen ? 'none' : 'block';
  }
}

function reportCurrentChallenge() {
  const challengeId = Number(document.body.dataset.challengeId) || Number(new URLSearchParams(window.location.search).get('id'));
  if (challengeId) {
    reportChallenge(challengeId);
  }
  const dropdown = safeGetById('optionsDropdown');
  if (dropdown) dropdown.style.display = 'none';
}

function deleteCurrentChallenge() {
  const challengeId = Number(document.body.dataset.challengeId) || Number(new URLSearchParams(window.location.search).get('id'));
  if (challengeId) {
    openConfirmDeleteModal(challengeId);
  }
  const dropdown = safeGetById('optionsDropdown');
  if (dropdown) dropdown.style.display = 'none';
}

function submitFlagFromDetail() {
  const challengeId = Number(document.body.dataset.challengeId) || Number(new URLSearchParams(window.location.search).get('id'));
  if (challengeId) {
    submitFlag(challengeId);
  }
}

function shareCurrentChallenge() {
  const challengeId = Number(document.body.dataset.challengeId) || Number(new URLSearchParams(window.location.search).get('id'));
  if (challengeId) {
    shareChallenge(challengeId);
  }
}

function toggleOptionsMenu(event) {
  if (event) event.stopPropagation();
  const dropdown = event ? event.target.closest('.challenge-options-dropdown')?.querySelector('.dropdown-menu') : safeGetById('optionsDropdown');
  if (dropdown) {
    const isOpen = dropdown.style.display === 'block';
    document.querySelectorAll('.dropdown-menu').forEach(m => m.style.display = 'none');
    dropdown.style.display = isOpen ? 'none' : 'block';
  }
}

async function openChallengeModal(challengeId, singlePageMode = false) {
  if (!currentUser) {
    showToast('⚠️ Please login to view challenges', 'error');
    window.location.href = 'login.html';
    return;
  }

  try {
    const response = await fetch(`${API_BASE_URL}/challenges/${challengeId}`);
    if (!response.ok) {
      throw new Error('Challenge lookup failed');
    }

    const challenge = await response.json();
    renderChallengeModal(challenge);

    const modal = safeGetById('challengeModal');
    if (modal) {
      modal.classList.add('active');
    }

    if (singlePageMode) {
      const title = safeGetById('challengeTitle');
      if (title) title.textContent = challenge.title;
    }
  } catch (error) {
    console.error('Error loading challenge details:', error);
    showToast('❌ Unable to load challenge', 'error');
  }
}

function renderChallengeModal(challenge) {
  const container = safeGetById('challengeDetails');
  if (!container) return;

  container.innerHTML = `
    <div class="modal-card-inner">
      <div class="modal-header-bar">
        <div class="modal-meta-left">
          <div class="card-category-icon"><svg viewBox="0 0 64 64" width="20" height="21"><use href="/logo.svg#eagle"/></svg></div>
          <span class="card-category-name">r/${escapeHtml(challenge.category || 'OSINT')}</span>
          <span class="card-time-ago">• ${challenge.created_at ? new Date(challenge.created_at).toLocaleDateString() : 'Today'}</span>
          <span class="card-category-badge">${escapeHtml(challenge.difficulty || 'Open')}</span>
        </div>
        <div class="card-meta-right">
          <a class="card-joined-pill" href="challenge_detail.html?id=${challenge.id}">
            <i class="fa-solid fa-play"></i> Open
          </a>
          <button class="card-options-btn" type="button" aria-label="More options" onclick="event.stopPropagation(); toggleOptionsMenu(event)">
            <i class="fa-solid fa-ellipsis"></i>
          </button>
          <div class="dropdown-menu">
            <button class="dropdown-item" onclick="shareChallenge(${challenge.id})">
              <i class="fa-solid fa-share"></i> Share
            </button>
            <button class="dropdown-item" onclick="reportChallenge(${challenge.id})">
              <i class="fa-solid fa-flag"></i> Report
            </button>
            ${currentUser && Number(challenge.created_by) === Number(currentUser.id) ? `<button class="dropdown-item dropdown-danger" onclick="removeChallenge(${challenge.id})">
              <i class="fa-solid fa-trash"></i> Delete
            </button>` : ''}
          </div>
        </div>
      </div>

      <div class="modal-title">${escapeHtml(challenge.title)}</div>

      <div class="modal-media">
        ${renderMedia(challenge.telegram_file_id ? challenge.telegram_file_id : '')}
      </div>

      <div class="modal-description">
        ${escapeHtml(challenge.description || '')}
      </div>

      ${challenge.can_view_walkthrough && challenge.solution_walkthrough ? `
        <div class="walkthrough-box">
          <div class="walkthrough-header">
            <i class="fa-solid fa-lightbulb"></i>
            <strong>Solution Walkthrough</strong>
          </div>
          <div class="walkthrough-body">${escapeHtml(challenge.solution_walkthrough)}</div>
        </div>
      ` : ''}

      <div class="modal-meta-grid">
        <div class="modal-meta-card">
          <span class="meta-label">Reward</span>
          <strong>${challenge.points_reward} Coins</strong>
        </div>
        <div class="modal-meta-card">
          <span class="meta-label">Solved</span>
          <strong>${challenge.solved_count || 0} Analysts</strong>
        </div>
        <div class="modal-meta-card">
          <span class="meta-label">Created</span>
          <strong>${challenge.created_at ? new Date(challenge.created_at).toLocaleDateString() : 'Today'}</strong>
        </div>
      </div>

      <div class="modal-action-bar">
        <button class="vote-pill" type="button" onclick="event.stopPropagation();">
          <span class="vote-arrow"><i class="fa-solid fa-arrow-up"></i></span>
          <span class="vote-count">${challenge.points_reward || 100}</span>
          <span class="vote-arrow"><i class="fa-solid fa-arrow-down"></i></span>
        </button>
        <a class="action-pill" href="challenge_detail.html?id=${challenge.id}">
          <i class="fa-solid fa-comment"></i> ${challenge.solved_count || 0} Solve
        </a>
        <button class="action-pill" type="button" onclick="event.stopPropagation(); shareChallenge(${challenge.id});">
          <i class="fa-solid fa-share"></i> Share
        </button>
      </div>
    </div>
  `;
}

function toggleComments() {
  const section = document.querySelector('.comments-section');
  if (section) {
    section.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
}

async function loadComments(challengeId) {
  const list = safeGetById('redditCommentsList');
  const countLabel = safeGetById('totalCommentsCount');
  const composer = safeGetById('commentsComposerTop');
  if (!list) return;

  try {
    const response = await fetch(`${API_BASE_URL}/challenges/${challengeId}/comments`);
    if (!response.ok) throw new Error('Comments fetch failed');
    const comments = await response.json();

    if (countLabel) countLabel.textContent = comments.length;

    if (!comments.length) {
      list.innerHTML = '<div class="comments-empty">No discussion yet. Be the first to share a thought.</div>';
    } else {
      const sorted = sortComments(comments, commentsSortMode);
      list.innerHTML = sorted.map((comment) => renderRedditComment(comment, challengeId, 0)).join('');
    }

    if (composer) {
      composer.innerHTML = currentUser
        ? `
          <div class="comment-form" style="margin-bottom:24px;">
            <textarea id="commentInput" maxlength="2000" placeholder="Share your findings, hints, or feedback..." rows="3"></textarea>
            <div class="comment-form-meta">
              <span id="commentCharCount">0 / 2000</span>
              <button type="button" class="btn btn-primary btn-small" onclick="submitTopLevelComment(${challengeId})">Post Comment</button>
            </div>
          </div>
        `
        : `<div class="comment-login-prompt" style="margin-bottom:24px;">Sign in to join the discussion.</div>`;
    }

    const input = safeGetById('commentInput');
    if (input) {
      const counter = safeGetById('commentCharCount');
      input.addEventListener('input', () => {
        if (counter) counter.textContent = `${input.value.length} / 2000`;
      });
    }
  } catch (error) {
    console.error('Error loading comments:', error);
    list.innerHTML = '<div class="comments-empty">Unable to load discussion.</div>';
  }
}

let commentsSortMode = 'best';

function sortComments(comments, mode) {
  const list = [...comments];
  if (mode === 'new') {
    return list.sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0));
  }
  if (mode === 'top') {
    return list.sort((a, b) => (b.upvotes || 0) - (a.upvotes || 0));
  }
  if (mode === 'controversial') {
    return list.sort((a, b) => {
      const aScore = (a.upvotes || 0) + (a.downvotes || 0);
      const bScore = (b.upvotes || 0) + (b.downvotes || 0);
      return bScore - aScore;
    });
  }
  return list.sort((a, b) => {
    const aScore = (a.upvotes || 0) * 2;
    const bScore = (b.upvotes || 0) * 2;
    return bScore - aScore;
  });
}

function setupCommentsPage() {
  const challengeId = Number(new URLSearchParams(window.location.search).get('id'));
  if (!challengeId) return;

  document.querySelectorAll('.sort-btn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      commentsSortMode = btn.dataset.sort || 'best';
      document.querySelectorAll('.sort-btn').forEach((item) => {
        item.classList.toggle('active', item.dataset.sort === commentsSortMode);
      });
      await loadComments(challengeId);
    });
  });
}

function getInitials(name) {
  if (!name) return '?';
  const parts = name.trim().split(' ');
  if (parts.length >= 2) {
    return (parts[0][0] + parts[1][0]).toUpperCase();
  }
  return name.substring(0, 2).toUpperCase();
}

function getAvatarColor(name) {
  if (!name) return 'var(--primary)';
  let hash = 0;
  for (let i = 0; i < name.length; i++) {
    hash = name.charCodeAt(i) + ((hash << 5) - hash);
  }
  const hue = Math.abs(hash % 360);
  return `hsl(${hue}, 65%, 60%)`;
}

function renderRedditComment(comment, challengeId, depth) {
  const voteCount = comment.upvotes || 0;
  const isCollapsed = comment.collapsed ? 'collapsed' : '';
  const collapseIcon = comment.collapsed ? 'fa-plus' : 'fa-minus';
  const repliesHtml = (comment.replies || []).map((reply) => renderRedditComment(reply, challengeId, depth + 1)).join('');
  const initials = getInitials(comment.username);
  const avatarColor = getAvatarColor(comment.username);

  return `
    <div class="reddit-comment ${isCollapsed}" data-comment-id="${comment.id}">
      <div class="vote-column">
        <button class="vote-btn" type="button" onclick="voteComment(this, 1)" title="Upvote" aria-label="Upvote">
          <i class="fa-solid fa-arrow-up"></i>
        </button>
        <div class="vote-count">${voteCount}</div>
        <button class="vote-btn" type="button" onclick="voteComment(this, -1)" title="Downvote" aria-label="Downvote">
          <i class="fa-solid fa-arrow-down"></i>
        </button>
      </div>
      <div class="comment-body-wrap">
        <div class="comment-meta">
          <button class="collapse-btn" onclick="toggleCollapse(this)">
            <i class="fa-solid ${collapseIcon}"></i>
          </button>
          <div class="comment-avatar" style="background:${avatarColor};" title="${escapeHtml(comment.username || 'unknown')}">
            ${escapeHtml(initials)}
          </div>
          <span class="comment-author">${escapeHtml(comment.username || 'unknown')}</span>
          <span class="comment-badge">Analyst</span>
          <span class="comment-time">${comment.created_at ? new Date(comment.created_at).toLocaleString() : 'just now'}</span>
        </div>
        <div class="comment-text">${escapeHtml(comment.body || '')}</div>
        <div class="comment-actions-bar">
          <button class="comment-action" onclick="replyToComment(${comment.id}, ${challengeId})">
            <i class="fa-solid fa-reply"></i> Reply
          </button>
          <button class="comment-action" onclick="shareComment(${comment.id})">
            <i class="fa-solid fa-share"></i> Share
          </button>
          <button class="comment-action" type="button" onclick="reportComment(${comment.id}, ${challengeId})">
            <i class="fa-solid fa-flag"></i> Report
          </button>
        </div>
        ${repliesHtml ? `<div class="replies-thread">${repliesHtml}</div>` : ''}
      </div>
    </div>
  `;
}

function toggleCollapse(btn) {
  const comment = btn.closest('.reddit-comment');
  if (comment) {
    comment.classList.toggle('collapsed');
    const icon = btn.querySelector('i');
    if (icon) {
      icon.className = comment.classList.contains('collapsed') ? 'fa-solid fa-plus' : 'fa-solid fa-minus';
    }
  }
}

async function submitTopLevelComment(challengeId) {
  const input = safeGetById('commentInput');
  if (!input) return;
  const body = input.value.trim();
  if (!body) {
    showToast('⚠️ Please write a comment', 'error');
    return;
  }

  const token = localStorage.getItem('token');
  if (!token) {
    showToast('⚠️ Please login to comment', 'error');
    return;
  }

  try {
    const response = await fetch(`${API_BASE_URL}/challenges/${challengeId}/comments`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify({ body })
    });

    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      showToast(data.detail || 'Failed to post comment', 'error');
      return;
    }

    input.value = '';
    showToast('✅ Comment posted', 'success');
    await loadComments(challengeId);
  } catch (error) {
    console.error('Error posting comment:', error);
    showToast('❌ Unable to post comment', 'error');
  }
}

async function replyToComment(parentId, challengeId) {
  if (!currentUser) {
    showToast('⚠️ Please login to reply', 'error');
    return;
  }

  const body = prompt('Write your reply:');
  if (!body || !body.trim()) return;

  const token = localStorage.getItem('token');
  if (!token) {
    showToast('⚠️ Session expired', 'error');
    return;
  }

  try {
    const response = await fetch(`${API_BASE_URL}/challenges/${challengeId}/comments`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify({ body: body.trim(), parent_id: parentId })
    });

    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      showToast(data.detail || 'Reply failed', 'error');
      return;
    }

    showToast('✅ Reply posted', 'success');
    await loadComments(challengeId);
  } catch (error) {
    console.error('Error posting reply:', error);
    showToast('❌ Unable to post reply', 'error');
  }
}

function voteComment(button, direction) {
  const comment = button?.closest('.reddit-comment');
  const count = comment?.querySelector('.vote-count');
  if (!comment || !count) return;

  const activeClass = direction > 0 ? 'upvoted' : 'downvoted';
  const oppositeClass = direction > 0 ? 'downvoted' : 'upvoted';
  const wasActive = button.classList.contains(activeClass);
  const oppositeButton = comment.querySelector(`.vote-btn.${oppositeClass}`);
  const switchedVote = !wasActive && Boolean(oppositeButton);
  comment.querySelectorAll('.vote-btn').forEach((item) => item.classList.remove('upvoted', 'downvoted'));
  const currentScore = Number(count.textContent) || 0;
  const nextScore = wasActive
    ? currentScore - direction
    : currentScore + direction * (switchedVote ? 2 : 1);
  button.classList.toggle(activeClass, !wasActive);
  count.textContent = nextScore;
}

function shareComment(commentId) {
  const url = `${window.location.origin}${window.location.pathname.replace('comments.html', '')}comments.html#comment-${commentId}`;
  if (navigator.clipboard) {
    navigator.clipboard.writeText(url).then(() => {
      showToast('🔗 Comment link copied', 'success');
    }).catch(() => {
      showToast('🔗 Share: ' + url, 'success');
    });
  } else {
    showToast('🔗 Share: ' + url, 'success');
  }
}

function reportComment(commentId, challengeId) {
  reportChallenge(challengeId, 'comment');
  reportCommentId = commentId;
}

async function unlockHint(challengeId, hintNumber) {
  if (!currentUser) {
    showToast('⚠️ Please login', 'error');
    return;
  }

  const token = localStorage.getItem('token');
  if (!token) {
    showToast('⚠️ Session expired', 'error');
    window.location.href = 'login.html';
    return;
  }

  try {
    const response = await fetch(`${API_BASE_URL}/hints/unlock`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify({ challenge_id: challengeId, hint_number: hintNumber })
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      showToast(`❌ ${data.detail || 'Unable to unlock hint'}`, 'error');
      return;
    }

    showHintModal(hintNumber, data.hint_text, data.remaining_coins);
    currentUser.coins = data.remaining_coins;
    localStorage.setItem('user', JSON.stringify(currentUser));
    setUserDisplayState();
  } catch (error) {
    showToast('❌ Error unlocking hint', 'error');
  }
}

function showHintModal(hintNumber, hintText, remainingCoins) {
  let modal = safeGetById('hintModal');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'hintModal';
    modal.className = 'modal';
    modal.innerHTML = `
      <div class="modal-card hint-modal-card">
        <button class="modal-close" aria-label="Close hint panel">&times;</button>
        <div class="hint-modal-header">
          <div class="hint-modal-icon"><i class="fa-solid fa-lightbulb"></i></div>
          <div>
            <span class="eyebrow">Insight</span>
            <h3 id="hintModalTitle">Hint Unlocked</h3>
          </div>
        </div>
        <div class="hint-modal-body">
          <div class="hint-modal-label">Hint Content</div>
          <div id="hintModalText" class="hint-modal-text"></div>
        </div>
        <div class="hint-modal-footer">
          <div class="hint-modal-coins">
            <i class="fa-solid fa-coins"></i>
            <span><strong id="hintModalCoins">0</span> coins remaining</span>
          </div>
          <button class="btn btn-primary btn-small" type="button" onclick="closeHintModal()">Got it</button>
        </div>
      </div>
    `;
    document.body.appendChild(modal);
  }

  const title = safeGetById('hintModalTitle');
  const text = safeGetById('hintModalText');
  const coins = safeGetById('hintModalCoins');

  if (title) title.textContent = `Hint ${hintNumber} Unlocked`;
  if (text) text.textContent = hintText;
  if (coins) coins.textContent = remainingCoins;

  modal.classList.add('active');
}

function closeHintModal() {
  const modal = safeGetById('hintModal');
  if (modal) modal.classList.remove('active');
}

async function submitFlag(challengeId) {
  if (!currentUser) {
    showToast('⚠️ Please login', 'error');
    return;
  }

  const flagInput = safeGetById('flagInput');
  const flag = flagInput ? flagInput.value.trim() : '';

  if (!flag) {
    showToast('⚠️ Please enter a flag', 'error');
    return;
  }

  const token = localStorage.getItem('token');
  if (!token) {
    showToast('⚠️ Session expired', 'error');
    window.location.href = 'login.html';
    return;
  }

  try {
    const response = await fetch(`${API_BASE_URL}/challenges/submit`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`
      },
      body: JSON.stringify({ challenge_id: challengeId, flag })
    });

    const data = await response.json().catch(() => ({}));

    if (!response.ok) {
      showToast(`❌ ${data.detail || 'Submission failed'}`, 'error');
      return;
    }

    if (data.success) {
      currentUser.coins = data.total_coins;
      currentUser.rank_points = data.rank_points;
      currentUser.solved_challenges = Array.isArray(currentUser.solved_challenges)
        ? [...currentUser.solved_challenges, challengeId]
        : [challengeId];
      currentUser.solved_count = (currentUser.solved_count || 0) + 1;
      localStorage.setItem('user', JSON.stringify(currentUser));
      setUserDisplayState();
      showToast(data.message || '✅ Correct answer!', 'success');

      const modal = safeGetById('challengeModal');
      if (modal) modal.classList.remove('active');

      renderChallenges();
      renderCommunityChallenges();
      await loadLeaderboard();
    } else {
      showToast(data.message || 'Incorrect flag', 'error');
    }
  } catch (error) {
    showToast('❌ Error submitting flag', 'error');
  }
}

// Single source of truth for challenge list filtering. Both the
// difficulty buttons and the search box read/write this state and
// then call `applyChallengeFilters` to re-render.
const challengeFilters = {
  difficulty: 'all',
  searchTerm: '',
};


function applyChallengeFilters() {
  const term = (challengeFilters.searchTerm || '').trim().toLowerCase();
  const difficulty = challengeFilters.difficulty || 'all';

  filteredChallenges = allChallenges.filter((challenge) => {
    if (difficulty !== 'all' && challenge.difficulty !== difficulty) {
      return false;
    }
    if (!term) {
      return true;
    }
    // Search across title, description, category and tags (tags is a
    // comma-separated string in the DB).
    const haystack = [
      challenge.title || '',
      challenge.description || '',
      challenge.category || '',
      challenge.tags || '',
    ].join(' ').toLowerCase();
    return haystack.includes(term);
  });

  renderChallenges();
}


function filterChallenges(difficulty = 'all') {
  const normalized = difficulty || 'all';
  const filterButtons = document.querySelectorAll('.filter-btn');
  filterButtons.forEach((button) => {
    button.classList.toggle('active', (button.dataset.filter || 'all') === normalized);
  });

  challengeFilters.difficulty = normalized;
  applyChallengeFilters();
}


function handleSearch(query) {
  challengeFilters.searchTerm = (query || '').trim();
  applyChallengeFilters();
}

function loadLeaderboard() {
  const widget = safeGetById('leaderboardWidget');
  if (!widget) return Promise.resolve();
  return fetchLeaderboard(5).then((leaderboard) => {
    if (!leaderboard.length) {
      widget.innerHTML = '<div class="loading-small">No users yet</div>';
      return;
    }
    widget.innerHTML = leaderboard.map((user) => `
      <div class="leaderboard-item">
        <span class="rank-badge ${user.rank <= 3 ? 'top3' : ''}">
          ${user.rank <= 3 ? ['🥇', '🥈', '🥉'][user.rank - 1] : '#' + user.rank}
        </span>
        <span class="username">${escapeHtml(user.username)}</span>
        <span class="points">${user.rank_points}pt</span>
      </div>
    `).join('');
  }).catch((error) => {
    console.error('Error loading leaderboard:', error);
  });
}

async function fetchLeaderboard(limit = 100) {
  const response = await fetch(`${API_BASE_URL}/leaderboard?limit=${limit}`);
  if (!response.ok) throw new Error('Leaderboard fetch failed');
  return response.json();
}

const BADGE_META = {
  rookie: { label: 'Rookie', tone: 'bronze', icon: 'fa-seedling' },
  resolver: { label: 'Resolver', tone: 'silver', icon: 'fa-crosshairs' },
  investigator: { label: 'Investigator', tone: 'gold', icon: 'fa-medal' },
  collector: { label: 'Collector', tone: '', icon: 'fa-coins' },
  guardian: { label: 'Guardian', tone: 'indigo', icon: 'fa-shield-halved' }
};

function renderBadgePills(badges) {
  if (!badges || !badges.length) return '<span class="meta-label">—</span>';
  return badges.map((id) => {
    const meta = BADGE_META[id] || { label: id, tone: '', icon: 'fa-award' };
    return `<span class="mini-badge ${meta.tone}"><i class="fa-solid ${meta.icon}"></i> ${meta.label}</span>`;
  }).join('');
}

async function loadFullLeaderboard() {
  const body = safeGetById('leaderboardBody');
  const userLabel = safeGetById('currentUserLabel');
  if (userLabel && currentUser) userLabel.textContent = currentUser.username || 'Analyst';

  if (!body) return;

  try {
    const leaderboard = await fetchLeaderboard(100);

    const yourRankEl = safeGetById('yourRank');
    const yourPointsEl = safeGetById('yourPoints');
    const yourSolvesEl = safeGetById('yourSolves');
    const totalEl = safeGetById('totalAnalysts');

    const myId = currentUser?.id || null;
    const me = myId ? leaderboard.find((u) => Number(u.user_id) === Number(myId)) : null;

    if (me) {
      if (yourRankEl) yourRankEl.textContent = `#${me.rank}`;
      if (yourPointsEl) yourPointsEl.textContent = me.rank_points;
      if (yourSolvesEl) yourSolvesEl.textContent = me.solved_count;
    } else if (yourRankEl) {
      yourRankEl.textContent = '—';
      if (yourPointsEl) yourPointsEl.textContent = '—';
      if (yourSolvesEl) yourSolvesEl.textContent = '—';
    }
    if (totalEl) totalEl.textContent = leaderboard.length;

    if (!leaderboard.length) {
      body.innerHTML = '<tr><td colspan="5" class="comments-empty">No analysts yet.</td></tr>';
      return;
    }

    body.innerHTML = leaderboard.map((user) => {
      const rankClass = user.rank === 1 ? 'top1' : user.rank === 2 ? 'top2' : user.rank === 3 ? 'top3' : '';
      const rankLabel = user.rank <= 3 ? ['🥇','🥈','🥉'][user.rank - 1] : `#${user.rank}`;
      const initial = (user.username || '?').charAt(0).toUpperCase();
      const isYou = Number(user.user_id) === Number(myId);
      return `
        <tr class="${isYou ? 'you' : ''}">
          <td><span class="rank-pill ${rankClass}">${rankLabel}</span></td>
          <td>
            <div class="user-cell">
              <span class="user-avatar">${escapeHtml(initial)}</span>
              <div>
                <strong>${escapeHtml(user.username)}</strong>
                ${isYou ? '<div class="meta-label">You</div>' : ''}
              </div>
            </div>
          </td>
          <td>${user.rank_points} pts</td>
          <td>${user.solved_count}</td>
          <td><div class="badge-stack">${renderBadgePills(user.badges)}</div></td>
        </tr>
      `;
    }).join('');
  } catch (error) {
    console.error('Error loading leaderboard page:', error);
    body.innerHTML = '<tr><td colspan="5" class="comments-empty">Unable to load leaderboard.</td></tr>';
  }
}

function claimDailyBonus() {
  if (!currentUser) {
    showToast('⚠️ Please login to claim bonus', 'error');
    window.location.href = 'login.html';
    return;
  }

  const todayKey = getBonusClaimKey();
  const storageKey = getBonusStorageKey();
  const claimedKey = localStorage.getItem(storageKey);

  if (claimedKey === todayKey) {
    showToast('⚠️ Bonus already claimed today', 'error');
    updateBonusButtonState();
    return;
  }

  const token = localStorage.getItem('token');
  if (!token) {
    showToast('⚠️ Session expired', 'error');
    return;
  }

  const bonusButton = safeGetById('bonusBtn') || safeGetById('claimBonusBtn');
  if (bonusButton) bonusButton.disabled = true;
  fetch(`${API_BASE_URL}/profile/daily-bonus`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` }
  })
    .then(async (response) => {
      const data = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(data.detail || 'Unable to claim daily bonus');
      currentUser.coins = data.total_coins;
      localStorage.setItem('user', JSON.stringify(currentUser));
      localStorage.setItem(storageKey, todayKey);
      setUserDisplayState();
      showToast('🎁 +10 Coins claimed!', 'success');
      updateBonusButtonState();
    })
    .catch((error) => {
      if (error.message === 'Daily bonus already claimed today') {
        localStorage.setItem(storageKey, todayKey);
        updateBonusButtonState();
        showToast('⚠️ Bonus already claimed today', 'error');
        return;
      }
      showToast(`❌ ${error.message}`, 'error');
      updateBonusButtonState();
    })
    .finally(() => {
      if (bonusButton && localStorage.getItem(storageKey) !== todayKey) {
        bonusButton.disabled = false;
      }
    });
}

async function loadProfile() {
  if (!currentUser) return;

  const token = localStorage.getItem('token');
  if (!token) {
    window.location.href = 'login.html';
    return;
  }

  try {
    const response = await fetch(`${API_BASE_URL}/profile`, {
      headers: {
        Authorization: `Bearer ${token}`
      }
    });

    if (!response.ok) {
      throw new Error('Profile fetch failed');
    }

    const profile = await response.json();
    currentUser = { ...currentUser, ...profile };
    localStorage.setItem('user', JSON.stringify(currentUser));
    setUserDisplayState();

    const profileUsername = safeGetById('profileUsername');
    const profileEmail = safeGetById('profileEmail');
    const profileCoins = safeGetById('profileCoins');
    const profilePoints = safeGetById('profilePoints');
    const profileSolved = safeGetById('profileSolved');
    const profileBio = safeGetById('profileBio');
    const profileAvatar = safeGetById('profileAvatar');
    const profileTags = safeGetById('profileTags');
    const profileHistory = safeGetById('profileHistory');
    const profileCreated = safeGetById('profileCreated');
    const overviewCoins = safeGetById('overviewCoins');
    const overviewPoints = safeGetById('overviewPoints');
    const overviewSolved = safeGetById('overviewSolved');

    if (profileUsername) profileUsername.textContent = profile.username || currentUser.username;
    if (profileEmail) profileEmail.textContent = profile.email || '-';
    if (profileCoins) profileCoins.textContent = profile.coins || 0;
    if (profilePoints) profilePoints.textContent = profile.rank_points || 0;
    if (profileSolved) profileSolved.textContent = profile.solved_count || 0;
    if (overviewCoins) overviewCoins.textContent = profile.coins || 0;
    if (overviewPoints) overviewPoints.textContent = profile.rank_points || 0;
    if (overviewSolved) overviewSolved.textContent = profile.solved_count || 0;

    if (profile.telegram_chat_id) {
      currentUser.telegram_chat_id = profile.telegram_chat_id;
    }
    if (profile.telegram_notifications !== undefined) {
      currentUser.telegram_notifications = profile.telegram_notifications;
    }

    if (profileBio) {
      profileBio.textContent = profile.bio || 'No bio yet. Click Edit Profile to add one.';
    }

    if (profileAvatar) {
      if (profile.avatar_url) {
        profileAvatar.innerHTML = `<img src="${escapeHtml(profile.avatar_url)}" alt="Avatar" style="width:100%;height:100%;object-fit:cover;border-radius:50%;">`;
      } else {
        profileAvatar.innerHTML = '<i class="fa-solid fa-user-astronaut"></i>';
      }
    }

    if (profileTags) {
      const tags = [
        profile.solved_count > 0 ? 'Case Resolved' : 'Fresh Operator',
        profile.rank_points > 0 ? 'Ranked' : 'Unranked'
      ];
      profileTags.innerHTML = tags.map((tag) => `<span class="tag">${tag}</span>`).join('');
    }

    if (profileHistory) {
      const solved = Array.isArray(profile.solved_challenges) ? profile.solved_challenges : [];
      if (!solved.length) {
        profileHistory.innerHTML = '<div class="history-empty">No cases solved yet.</div>';
      } else {
        profileHistory.innerHTML = solved.map((item) => `
          <div class="history-item">
            <span class="history-title">${escapeHtml(item.title || `Case #${item.id}`)}</span>
            <span class="history-meta">${escapeHtml(item.difficulty || 'Unranked')}${item.solved_at ? ` · ${new Date(item.solved_at).toLocaleDateString()}` : ''}</span>
          </div>
        `).join('');
      }
    }

    if (profileCreated) {
      const created = Array.isArray(profile.created_challenges) ? profile.created_challenges : [];
      if (!created.length) {
        profileCreated.innerHTML = '<div class="history-empty">No cases created yet.</div>';
      } else {
        profileCreated.innerHTML = created.map((item) => `
          <div class="history-item">
            <div style="flex:1;min-width:0;">
              <span class="history-title">${escapeHtml(item.title || `Case #${item.id}`)}</span>
              <span class="history-meta">${escapeHtml(item.category || 'Uncategorized')} · ${escapeHtml(item.difficulty || 'Unranked')} · ${item.created_at ? new Date(item.created_at).toLocaleDateString() : 'Unknown date'}</span>
            </div>
            <div class="history-actions">
              <button class="btn-edit" type="button" onclick="event.stopPropagation(); openEditModal(${item.id});">Edit</button>
            </div>
          </div>
        `).join('');
      }
    }
  } catch (error) {
    console.error('Error loading profile:', error);
    showToast('❌ Unable to load profile', 'error');
  }
}

function showToast(message, type = 'success') {
  const toast = safeGetById('toast');
  if (!toast) return;

  toast.textContent = message;
  toast.setAttribute('role', 'status');
  toast.setAttribute('aria-live', 'polite');
  toast.className = `toast show ${type}`;

  clearTimeout(showToast.timeoutId);
  showToast.timeoutId = setTimeout(() => {
    toast.classList.remove('show');
    toast.textContent = '';
    toast.className = 'toast';
  }, 3000);
}

function onTurnstileSuccessLogin(token) {
  const input = safeGetById('loginTurnstileToken');
  if (input) input.value = token || '';
}

function onTurnstileSuccessSignup(token) {
  const input = safeGetById('signupTurnstileToken');
  if (input) input.value = token || '';
}

function onTurnstileSuccessForgot(token) {
  const input = safeGetById('forgotTurnstileToken');
  if (input) input.value = token || '';
}

function setupForgotPassword() {
  const forgotLink = safeGetById('forgotPasswordLink');
  if (forgotLink) {
    forgotLink.addEventListener('click', (event) => {
      event.preventDefault();
      const modal = safeGetById('forgotPasswordModal');
      if (modal) modal.classList.add('active');
    });
  }

  const forgotForm = safeGetById('forgotPasswordForm');
  if (forgotForm) {
    forgotForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      const username = safeGetById('forgotPasswordUsername')?.value?.trim();
      const turnstileToken = safeGetById('forgotTurnstileToken')?.value;
      const messageEl = safeGetById('forgotPasswordMessage');
      if (!username) {
        if (messageEl) {
          messageEl.textContent = 'Please enter your username';
          messageEl.className = 'form-message show error';
        }
        return;
      }
      try {
        const response = await fetch(`${API_BASE_URL}/auth/password-reset/request`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, turnstile_token: turnstileToken || null })
        });
        const data = await response.json().catch(() => ({}));
        if (messageEl) {
          if (response.ok) {
            messageEl.textContent = data.message || 'If Telegram is connected, a reset token has been sent.';
            messageEl.className = 'form-message show success';
            const resetModal = safeGetById('resetPasswordModal');
            if (resetModal) {
              setTimeout(() => {
                const forgotModal = safeGetById('forgotPasswordModal');
                if (forgotModal) forgotModal.classList.remove('active');
                resetModal.classList.add('active');
              }, 1500);
            }
          } else {
            messageEl.textContent = data.detail || 'Unable to send reset token';
            messageEl.className = 'form-message show error';
          }
        }
      } catch (error) {
        if (messageEl) {
          messageEl.textContent = 'Network error';
          messageEl.className = 'form-message show error';
        }
      }
    });
  }

  const resetForm = safeGetById('resetPasswordForm');
  if (resetForm) {
    resetForm.addEventListener('submit', async (event) => {
      event.preventDefault();
      const token = safeGetById('resetTokenInput')?.value?.trim();
      const newPassword = safeGetById('newPasswordReset')?.value;
      const messageEl = safeGetById('resetPasswordMessage');
      if (!token || !newPassword) {
        if (messageEl) {
          messageEl.textContent = 'Please provide both token and new password';
          messageEl.className = 'form-message show error';
        }
        return;
      }
      if (newPassword.length < 8 || !/[A-Za-z]/.test(newPassword) || !/\d/.test(newPassword)) {
        if (messageEl) {
          messageEl.textContent = 'Password must be 8+ chars and contain a letter and a digit';
          messageEl.className = 'form-message show error';
        }
        return;
      }
      try {
        const response = await fetch(`${API_BASE_URL}/auth/password-reset/confirm`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ reset_token: token, new_password: newPassword })
        });
        const data = await response.json().catch(() => ({}));
        if (response.ok) {
          if (messageEl) {
            messageEl.textContent = 'Password reset successful. You can now sign in.';
            messageEl.className = 'form-message show success';
          }
          setTimeout(() => {
            const modal = safeGetById('resetPasswordModal');
            if (modal) modal.classList.remove('active');
            const loginForm = safeGetById('loginForm');
            if (loginForm) {
              const usernameInput = safeGetById('loginUsername');
              if (usernameInput) usernameInput.focus();
            }
          }, 2000);
        } else {
          if (messageEl) {
            messageEl.textContent = data.detail || 'Password reset failed';
            messageEl.className = 'form-message show error';
          }
        }
      } catch (error) {
        if (messageEl) {
          messageEl.textContent = 'Network error';
          messageEl.className = 'form-message show error';
        }
      }
    });
  }

  // Password toggle (eye icon) is handled by global event delegation
  // in bindGlobalEvents() — no per-modal wiring needed here.
}

function initNetworkAnimation() {
  const canvas = document.getElementById('networkCanvas');
  if (!canvas) return;

  const ctx = canvas.getContext('2d');
  let particles = [];
  let animationId = null;
  let started = false;

  function resize() {
    canvas.width = Math.max(window.innerWidth, 320);
    canvas.height = Math.max(window.innerHeight, 320);
  }

  class Particle {
    constructor() {
      this.reset();
    }

    reset() {
      this.x = Math.random() * canvas.width;
      this.y = Math.random() * canvas.height;
      this.vx = (Math.random() - 0.5) * 0.8;
      this.vy = (Math.random() - 0.5) * 0.8;
      this.size = Math.random() * 3 + 1.5;
    }

    update() {
      this.x += this.vx;
      this.y += this.vy;

      if (this.x < 0 || this.x > canvas.width) this.vx *= -1;
      if (this.y < 0 || this.y > canvas.height) this.vy *= -1;
    }

    draw() {
      ctx.beginPath();
      ctx.arc(this.x, this.y, this.size, 0, Math.PI * 2);
      ctx.fillStyle = 'rgba(91, 179, 255, 0.9)';
      ctx.fill();
    }
  }

  function initParticles() {
    particles = [];
    const area = canvas.width * canvas.height;
    const count = Math.min(Math.floor(area / 8000), 180);
    for (let i = 0; i < count; i++) {
      particles.push(new Particle());
    }
  }

  function animate() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    for (let i = 0; i < particles.length; i++) {
      particles[i].update();
      particles[i].draw();
    }

    for (let i = 0; i < particles.length; i++) {
      for (let j = i + 1; j < particles.length; j++) {
        const dx = particles[i].x - particles[j].x;
        const dy = particles[i].y - particles[j].y;
        const dist = Math.sqrt(dx * dx + dy * dy);

        if (dist < 160) {
          ctx.beginPath();
          ctx.moveTo(particles[i].x, particles[i].y);
          ctx.lineTo(particles[j].x, particles[j].y);
          ctx.strokeStyle = `rgba(109, 224, 208, ${0.35 * (1 - dist / 160)})`;
          ctx.lineWidth = 1.2;
          ctx.stroke();
        }
      }
    }

    animationId = requestAnimationFrame(animate);
  }

  function start() {
    if (started) return;
    started = true;
    canvas.style.display = 'block';
    resize();
    initParticles();
    animate();
  }

  let resizeTimeout;
  window.addEventListener('resize', () => {
    clearTimeout(resizeTimeout);
    resizeTimeout = setTimeout(() => {
      resize();
      initParticles();
    }, 150);
  });

  if (document.readyState === 'complete') {
    start();
  } else {
    window.addEventListener('load', start);
  }

  setTimeout(() => {
    if (!started) start();
  }, 300);
}
