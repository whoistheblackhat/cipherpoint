(() => {
  const API_BASE = '/api';
  const $ = (id) => document.getElementById(id);

  const token = () => localStorage.getItem('token') || '';
  const user = () => {
    try { return JSON.parse(localStorage.getItem('user') || 'null'); } catch { return null; }
  };

  function showMessage(el, text, kind) {
    if (!el) return;
    el.className = 'form-message show ' + (kind || 'info');
    el.textContent = text;
  }
  function hideMessage(el) {
    if (!el) return;
    el.className = 'form-message';
    el.textContent = '';
  }

  function showToast(message, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    toast.style.cssText = 'position:fixed;bottom:24px;right:24px;padding:12px 18px;border-radius:8px;color:#fff;font-size:0.9rem;z-index:9999;max-width:90vw;word-break:break-word;';
    if (type === 'success') toast.style.background = '#3fb950';
    else if (type === 'error') toast.style.background = '#f85149';
    else toast.style.background = '#58a6ff';
    document.body.appendChild(toast);
    setTimeout(() => { toast.remove(); }, 3000);
  }

  async function uploadMediaFile(file) {
    const formData = new FormData();
    formData.append('file', file);
    try {
      const res = await fetch(`${API_BASE}/upload/media`, {
        method: 'POST',
        headers: { Authorization: `Bearer ${token()}` },
        body: formData,
      });
      const data = await res.json();
      if (res.ok && data.file_id) return data.file_id;
      console.error('upload failed:', data);
      return null;
    } catch (err) {
      console.error('upload error:', err);
      return null;
    }
  }

  async function authedFetch(path, options = {}) {
    const headers = Object.assign(
      { 'Content-Type': 'application/json' },
      options.headers || {},
      token() ? { Authorization: `Bearer ${token()}` } : {}
    );
    const res = await fetch(API_BASE + path, Object.assign({}, options, { headers }));
    if (res.status === 401) {
      try {
        localStorage.removeItem('token');
        localStorage.removeItem('user');
      } catch {}
      window.location.href = 'login.html';
      return { ok: false, status: 401, data: { detail: 'Session expired' } };
    }
    let data = null;
    try { data = await res.json(); } catch { /* non-JSON */ }
    return { ok: res.ok, status: res.status, data };
  }

  async function init() {
    // Diagnostic: log what we see so the user can debug in console.
    console.log('[admin] init start');
    console.log('[admin] token length:', token().length);
    const storedUser = user();
    console.log('[admin] stored user:', storedUser);

    // Gate 1: must have a token.
    if (!token()) {
      console.log('[admin] no token → gate');
      $('adminGate').style.display = 'block';
      $('adminApp').style.display = 'none';
      return;
    }

    // Gate 2: always verify with the server. localStorage can be stale or
    // populated by an older version of the app that didn't set is_admin.
    let u = storedUser;
    console.log('[admin] fetching /api/auth/me...');
    const me = await authedFetch('/auth/me');
    console.log('[admin] /api/auth/me status:', me.status, 'ok:', me.ok);
    if (me.ok) {
      u = Object.assign({}, u || {}, me.data);
      try { localStorage.setItem('user', JSON.stringify(u)); } catch {}
      console.log('[admin] refreshed user from server:', u);
    } else {
      console.log('[admin] /api/auth/me failed, falling back to stored user');
    }

    if (!u || !u.is_admin) {
      console.log('[admin] not admin → gate. u:', u);
      $('adminGate').style.display = 'block';
      $('adminApp').style.display = 'none';
      return;
    }

    console.log('[admin] admin verified → showing panel');
    $('adminGate').style.display = 'none';
    $('adminApp').style.display = 'block';
    $('adminUsername').textContent = u.username || ('user#' + u.id);

    setupTabs();
    setupCreate();
    setupEdit();
    setupUsers();
    setupFlaggedUsers();
    setupModeration();

    await loadStats();
    await loadEditList();
    await loadFlaggedList();
    await loadModerationList();

    $('adminLogout').addEventListener('click', (e) => {
      e.preventDefault();
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      window.location.href = 'login.html';
    });
  }

  function setupTabs() {
    const tabs = document.querySelectorAll('.admin-tab');
    const panels = document.querySelectorAll('.admin-panel');
    tabs.forEach(tab => {
      tab.addEventListener('click', () => {
        const name = tab.dataset.tab;
        tabs.forEach(t => t.classList.toggle('active', t === tab));
        panels.forEach(p => p.classList.toggle('active', p.dataset.panel === name));
      });
    });
  }

  // -------- STATS --------
  async function loadStats() {
    try {
      const [usersRes, chRes, repRes, flaggedRes] = await Promise.all([
        authedFetch('/admin/users?limit=1'),
        authedFetch('/challenges?limit=1'),
        authedFetch('/moderation/reports'),
        authedFetch('/admin/users/flagged?limit=1')
      ]);
      if (usersRes.ok && usersRes.data && typeof usersRes.data.total === 'number') {
        $('statUsers').textContent = usersRes.data.total;
      } else {
        $('statUsers').textContent = '—';
      }
      if (chRes.ok && Array.isArray(chRes.data)) {
        $('statChallenges').textContent = chRes.data.length || '—';
      } else {
        $('statChallenges').textContent = '—';
      }
      if (repRes.ok && Array.isArray(repRes.data)) {
        $('statReports').textContent = repRes.data.length;
      } else {
        $('statReports').textContent = '—';
      }
      if (flaggedRes.ok && typeof flaggedRes.data.total === 'number') {
        $('statFlagged').textContent = flaggedRes.data.total;
      } else {
        $('statFlagged').textContent = '—';
      }
    } catch (err) {
      console.warn('loadStats failed', err);
    }
  }

  // -------- CREATE --------
  function setupCreate() {
    const form = $('adminCreateForm');
    const msg = $('adminCreateMessage');
    const fileInput = $('adminMedia');
    const fileIdInput = $('adminFileId');

    // Handle file selection → upload to Telegram → store file_id
    if (fileInput) {
      fileInput.addEventListener('change', async (e) => {
        const file = e.target.files?.[0];
        if (!file) return;

        // Clear stale file_id when user picks a new file
        if (fileIdInput) fileIdInput.value = '';

        const allowed = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'video/mp4', 'video/webm', 'video/quicktime'];
        if (!allowed.includes(file.type)) {
          showToast('❌ Unsupported file type', 'error');
          e.target.value = '';
          return;
        }
        const maxSize = file.type.startsWith('video') ? 50 * 1024 * 1024 : 10 * 1024 * 1024;
        if (file.size > maxSize) {
          showToast(`❌ File too large (max ${Math.round(maxSize / (1024 * 1024))}MB)`, 'error');
          e.target.value = '';
          return;
        }
        if (file.size === 0) {
          showToast('❌ File is empty', 'error');
          e.target.value = '';
          return;
        }

        showMessage(msg, 'Uploading media…', 'info');
        const fileId = await uploadMediaFile(file);
        if (fileId) {
          if (fileIdInput) fileIdInput.value = fileId;
          showMessage(msg, '✅ Media uploaded', 'success');
        } else {
          if (fileIdInput) fileIdInput.value = '';
          showMessage(msg, 'Media upload failed', 'error');
        }
      });
    }

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (form.dataset.busy === '1') return;  // double-submit guard
      form.dataset.busy = '1';
      const submitBtn = form.querySelector('button[type="submit"]');
      const originalLabel = submitBtn ? submitBtn.innerHTML : '';
      if (submitBtn) { submitBtn.disabled = true; }
      hideMessage(msg);
      const fd = new FormData(form);
      const payload = {
        title: (fd.get('title') || '').toString().trim(),
        category: (fd.get('category') || 'OSINT').toString().trim() || 'OSINT',
        difficulty: (fd.get('difficulty') || 'Medium').toString(),
        description: (fd.get('description') || '').toString().trim(),
        correct_flag: (fd.get('flag') || '').toString().trim(),
        telegram_file_id: (fd.get('telegram_file_id') || fileIdInput?.value || '').toString().trim(),
        points_reward: parseInt(fd.get('points') || '100', 10),
        hint_1: '',
        hint_1_cost: 10,
        solution_walkthrough: (fd.get('walkthrough') || '').toString().trim(),
        tags: (fd.get('tags') || '').toString().trim()
      };

      if (!payload.title || !payload.description || !payload.correct_flag) {
        showMessage(msg, 'Title, description, and flag are required.', 'error');
        form.dataset.busy = '';
        if (submitBtn) { submitBtn.disabled = false; submitBtn.innerHTML = originalLabel; }
        return;
      }
      showMessage(msg, 'Creating…', 'info');
      const res = await authedFetch('/challenges/create', {
        method: 'POST',
        body: JSON.stringify(payload)
      });
      if (res.ok) {
        showMessage(msg, `Created challenge #${res.data.id} — ${res.data.title}`, 'success');
        form.reset();
        await loadEditList();
        await loadStats();
      } else {
        showMessage(msg, (res.data && res.data.detail) || 'Failed to create challenge', 'error');
      }
      form.dataset.busy = '';
      if (submitBtn) { submitBtn.disabled = false; submitBtn.innerHTML = originalLabel; }
    });
  }

  // -------- EDIT / DELETE --------
  async function loadEditList() {
    const list = $('editChallengeList');
    const msg = $('editListMessage');
    hideMessage(msg);
    list.innerHTML = '<li style="text-align:center;color:#8b949e;">Loading…</li>';
    const res = await authedFetch('/challenges?limit=200');
    if (!res.ok) {
      list.innerHTML = '';
      showMessage(msg, 'Failed to load challenges.', 'error');
      return;
    }
    const items = Array.isArray(res.data) ? res.data : [];
    if (!items.length) {
      list.innerHTML = '<li style="text-align:center;color:#8b949e;">No challenges yet.</li>';
      return;
    }
    list.innerHTML = '';
    items.forEach(ch => {
      const li = document.createElement('li');
      const diff = (ch.difficulty || 'medium').toLowerCase();
      li.innerHTML = `
        <div class="meta-block">
          <div class="title">#${ch.id} — ${escapeHtml(ch.title || '(no title)')}</div>
          <div class="sub">${escapeHtml(ch.category || '')} · ${ch.points_reward || ch.points || 0} pts · <span class="tag ${diff}">${escapeHtml(ch.difficulty || 'Medium')}</span></div>
        </div>
        <button class="btn-icon" data-action="edit" data-id="${ch.id}"><i class="fa-solid fa-pen"></i> Edit</button>
        <button class="btn-icon danger" data-action="delete" data-id="${ch.id}" data-title="${escapeAttr(ch.title || '')}"><i class="fa-solid fa-trash"></i> Delete</button>
      `;
      list.appendChild(li);
    });
  }

  function setupEdit() {
    const list = $('editChallengeList');
    const modal = $('editChallengeModal');
    const editForm = $('adminEditForm');
    const editMsg = $('adminEditMessage');
    $('editCancel').addEventListener('click', () => modal.classList.remove('show'));

    list.addEventListener('click', async (e) => {
      const btn = e.target.closest('button[data-action]');
      if (!btn) return;
      const id = btn.dataset.id;
      if (btn.dataset.action === 'edit') {
        editMsg.className = 'form-message';
        editMsg.textContent = '';
        const res = await authedFetch('/challenges/' + id);
        if (!res.ok) {
          alert('Failed to load challenge');
          return;
        }
        const ch = res.data;
        editForm.elements['id'].value = ch.id;
        editForm.elements['title'].value = ch.title || '';
        editForm.elements['difficulty'].value = ch.difficulty || 'Medium';
        editForm.elements['points'].value = ch.points_reward || ch.points || 100;
        editForm.elements['description'].value = ch.description || '';
        editForm.elements['walkthrough'].value = ch.solution_walkthrough || ch.walkthrough || '';
        const editFileIdInput = document.getElementById('adminEditFileId');
        if (editFileIdInput) editFileIdInput.value = ch.telegram_file_id || '';
        modal.classList.add('show');
      } else if (btn.dataset.action === 'delete') {
        const title = btn.dataset.title || ('challenge #' + id);
        if (!confirm(`Delete "${title}"? This cannot be undone.`)) return;
        const res = await authedFetch('/challenges/' + id, { method: 'DELETE' });
        if (res.ok) {
          showMessage($('editListMessage'), 'Deleted.', 'success');
          await loadEditList();
        } else {
          showMessage($('editListMessage'), (res.data && res.data.detail) || 'Delete failed', 'error');
        }
      }
    });

    editForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (editForm.dataset.busy === '1') return;  // double-submit guard
      editForm.dataset.busy = '1';
      const saveBtn = editForm.querySelector('button[type="submit"]');
      const originalLabel = saveBtn ? saveBtn.innerHTML : '';
      if (saveBtn) { saveBtn.disabled = true; }
      editMsg.className = 'form-message';
      editMsg.textContent = '';
      const fd = new FormData(editForm);
      const id = fd.get('id');
      const payload = {
        title: (fd.get('title') || '').toString().trim(),
        difficulty: (fd.get('difficulty') || 'Medium').toString(),
        points_reward: parseInt(fd.get('points') || '100', 10),
        description: (fd.get('description') || '').toString().trim(),
        solution_walkthrough: (fd.get('walkthrough') || '').toString().trim(),
        hint_1: (fd.get('hint_1') || '').toString().trim() || null,
        hint_2: (fd.get('hint_2') || '').toString().trim() || null,
        hint_1_cost: parseInt(fd.get('hint_1_cost') || '0', 10),
        hint_2_cost: parseInt(fd.get('hint_2_cost') || '0', 10),
        tags: (fd.get('tags') || '').toString().trim() || null,
        telegram_file_id: (fd.get('telegram_file_id') || document.getElementById('adminEditFileId')?.value || '').toString().trim() || null,
      };
      showMessage(editMsg, 'Saving…', 'info');
      const res = await authedFetch('/challenges/' + id, {
        method: 'PUT',
        body: JSON.stringify(payload)
      });
      if (res.ok) {
        showMessage(editMsg, 'Saved.', 'success');
        await loadEditList();
        setTimeout(() => modal.classList.remove('show'), 600);
      } else {
        showMessage(editMsg, (res.data && res.data.detail) || 'Save failed', 'error');
      }
      editForm.dataset.busy = '';
      if (saveBtn) { saveBtn.disabled = false; saveBtn.innerHTML = originalLabel; }
    });

    const editFileInput = document.getElementById('adminEditMedia');
    const editFileIdInput = document.getElementById('adminEditFileId');
    if (editFileInput) {
      editFileInput.addEventListener('change', async (e) => {
        const file = e.target.files?.[0];
        if (!file) return;
        if (editFileIdInput) editFileIdInput.value = '';
        const allowed = ['image/jpeg', 'image/png', 'image/gif', 'image/webp', 'video/mp4', 'video/webm', 'video/quicktime'];
        if (!allowed.includes(file.type)) {
          showToast('❌ Unsupported file type', 'error');
          e.target.value = '';
          return;
        }
        const maxSize = file.type.startsWith('video') ? 50 * 1024 * 1024 : 10 * 1024 * 1024;
        if (file.size > maxSize) {
          showToast(`❌ File too large (max ${Math.round(maxSize / (1024 * 1024))}MB)`, 'error');
          e.target.value = '';
          return;
        }
        showToast('Uploading media…', 'info');
        const fileId = await uploadMediaFile(file);
        if (fileId) {
          if (editFileIdInput) editFileIdInput.value = fileId;
          showToast('✅ Media uploaded', 'success');
        } else {
          if (editFileIdInput) editFileIdInput.value = '';
          showToast('Media upload failed', 'error');
        }
      });
    }
  }

  // -------- USERS --------
  function setupUsers() {
    const search = $('userSearch');
    const btn = $('userSearchBtn');
    const list = $('userList');
    const msg = $('userListMessage');

    async function run() {
      hideMessage(msg);
      const q = (search.value || '').trim();
      if (!q) { list.innerHTML = '<li style="text-align:center;color:#8b949e;">Type a username, email, or ID.</li>'; return; }
      list.innerHTML = '<li style="text-align:center;color:#8b949e;">Searching…</li>';
      const res = await authedFetch(`/admin/users?q=${encodeURIComponent(q)}`);
      if (!res.ok) {
        list.innerHTML = '';
        showMessage(msg, (res.data && res.data.detail) || 'Search failed', 'error');
        return;
      }
      const users = Array.isArray(res.data) ? res.data : (res.data && res.data.items) || [];
      if (!users.length) {
        list.innerHTML = '<li style="text-align:center;color:#8b949e;">No matches.</li>';
        return;
      }
      list.innerHTML = '';
      users.forEach(u => {
        const li = document.createElement('li');
        const badges = [];
        if (u.is_admin) badges.push('<span class="tag admin">admin</span>');
        if (u.banned) badges.push('<span class="tag banned">banned</span>');
        if (u.is_active !== false && !u.banned) badges.push('<span class="tag active">active</span>');
        li.innerHTML = `
          <div class="meta-block">
            <div class="title">#${u.id} ${escapeHtml(u.username || '')} ${badges.join(' ')}</div>
            <div class="sub">${escapeHtml(u.email || '')} · ${u.coins || 0} coins · ${u.rank_points || 0} pts · joined ${escapeHtml(u.created_at || '')}</div>
          </div>
          <button class="btn-icon danger" data-action="ban" data-id="${u.id}" data-name="${escapeAttr(u.username || '')}"><i class="fa-solid fa-gavel"></i> Ban</button>
        `;
        list.appendChild(li);
      });
    }

    btn.addEventListener('click', run);
    search.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); run(); } });

    // Ban modal
    const banModal = $('banUserModal');
    const banForm = $('banUserForm');
    $('banCancel').addEventListener('click', () => banModal.classList.remove('show'));

    list.addEventListener('click', (e) => {
      const btn = e.target.closest('button[data-action="ban"]');
      if (!btn) return;
      banForm.elements['userId'].value = btn.dataset.id;
      banForm.elements['reason'].value = '';
      banForm.elements['days'].value = '0';
      banModal.classList.add('show');
    });

    banForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(banForm);
      const payload = {
        user_id: parseInt(fd.get('userId'), 10),
        reason: (fd.get('reason') || '').toString().trim(),
        days: parseInt(fd.get('days') || '0', 10)
      };
      const res = await authedFetch('/admin/users/ban', {
        method: 'POST',
        body: JSON.stringify(payload)
      });
      if (res.ok) {
        showMessage(msg, 'User banned.', 'success');
        banModal.classList.remove('show');
        run();
      } else {
        showMessage(msg, (res.data && res.data.detail) || 'Ban failed', 'error');
      }
    });
  }

  // -------- FLAGGED USERS --------
  function setupFlaggedUsers() {
    const list = $('flaggedList');
    const msg = $('flaggedListMessage');
  }

  async function loadFlaggedList() {
    const list = $('flaggedList');
    const msg = $('flaggedListMessage');
    hideMessage(msg);
    list.innerHTML = '<li style="text-align:center;color:#8b949e;">Loading…</li>';
    const res = await authedFetch('/admin/users/flagged?limit=200');
    if (!res.ok) {
      list.innerHTML = '';
      showMessage(msg, (res.data && res.data.detail) || 'Failed to load flagged users.', 'error');
      return;
    }
    const users = Array.isArray(res.data) ? res.data : (res.data && res.data.items) || [];
    if (!users.length) {
      list.innerHTML = '<li style="text-align:center;color:#8b949e;">No flagged users. Good job!</li>';
      return;
    }
    list.innerHTML = '';
    users.forEach(u => {
      const li = document.createElement('li');
      const badges = [];
      if (u.is_admin) badges.push('<span class="tag admin">admin</span>');
      if (u.banned) badges.push('<span class="tag banned">banned</span>');
      if (u.is_active !== false && !u.banned) badges.push('<span class="tag active">active</span>');
      const reason = u.fastest_solve_seconds !== null && u.fastest_solve_seconds < 5
        ? `Fast solve: ${u.fastest_solve_seconds}s`
        : (u.device_fingerprint_hash ? 'Duplicate fingerprint' : 'Unknown');
      li.innerHTML = `
        <div class="meta-block">
          <div class="title">#${u.id} ${escapeHtml(u.username || '')} ${badges.join(' ')}</div>
          <div class="sub">${escapeHtml(u.email || '')} · ${u.coins || 0} coins · ${u.rank_points || 0} pts · ${reason}</div>
        </div>
        <button class="btn-icon" data-action="unflag" data-id="${u.id}" data-name="${escapeAttr(u.username || '')}"><i class="fa-solid fa-rotate-left"></i> Unflag</button>
      `;
      list.appendChild(li);
    });

    list.addEventListener('click', async (e) => {
      const btn = e.target.closest('button[data-action="unflag"]');
      if (!btn) return;
      const id = btn.dataset.id;
      const res = await authedFetch('/admin/users/unflag', {
        method: 'POST',
        body: JSON.stringify({ user_id: parseInt(id, 10) })
      });
      if (res.ok) {
        showMessage(msg, `User #${id} unflagged.`, 'success');
        await loadFlaggedList();
        await loadStats();
      } else {
        showMessage(msg, (res.data && res.data.detail) || 'Unflag failed', 'error');
      }
    });
  }

  // -------- MODERATION --------
  async function loadModerationList() {
    const list = $('moderationList');
    const msg = $('moderationMessage');
    hideMessage(msg);
    list.innerHTML = '<li style="text-align:center;color:#8b949e;">Loading…</li>';
    const res = await authedFetch('/moderation/reports');
    if (!res.ok) {
      list.innerHTML = '';
      showMessage(msg, 'Failed to load reports.', 'error');
      return;
    }
    const reports = Array.isArray(res.data) ? res.data : [];
    if (!reports.length) {
      list.innerHTML = '<li style="text-align:center;color:#8b949e;">No open reports. Nice and quiet.</li>';
      return;
    }
    list.innerHTML = '';
    reports.forEach(r => {
      const li = document.createElement('li');
      li.innerHTML = `
        <div class="meta-block">
          <div class="title">Report #${r.id} — ${escapeHtml(r.target_type || 'challenge')} on "${escapeHtml(r.challenge_title || '')}"</div>
          <div class="sub"><b>Reporter:</b> ${escapeHtml(r.reporter || '?')} · <b>Reason:</b> ${escapeHtml(r.reason || '—')} · ${escapeHtml(r.created_at || '')}</div>
          ${r.comment_body ? `<div class="sub" style="margin-top:6px;padding:8px;background:#161b22;border-left:2px solid #f85149;">${escapeHtml(r.comment_body)}</div>` : ''}
        </div>
        <button class="btn-icon" data-action="approve" data-id="${r.id}"><i class="fa-solid fa-check"></i> Approve</button>
        <button class="btn-icon" data-action="reject" data-id="${r.id}"><i class="fa-solid fa-xmark"></i> Reject</button>
        <button class="btn-icon danger" data-action="ban" data-id="${r.id}"><i class="fa-solid fa-gavel"></i> Ban</button>
      `;
      list.appendChild(li);
    });
  }

  function setupModeration() {
    const list = $('moderationList');
    const msg = $('moderationMessage');
    list.addEventListener('click', async (e) => {
      const btn = e.target.closest('button[data-action]');
      if (!btn) return;
      const id = btn.dataset.id;
      const action = btn.dataset.action;
      const reason = prompt(`Reason for ${action} (optional):`) || '';
      hideMessage(msg);
      const res = await authedFetch(`/moderation/reports/${id}/resolve`, {
        method: 'POST',
        body: JSON.stringify({ action, reason })
      });
      if (res.ok) {
        showMessage(msg, `Report #${id} resolved (${action}).`, 'success');
        await loadModerationList();
        await loadStats();
      } else {
        showMessage(msg, (res.data && res.data.detail) || 'Resolve failed', 'error');
      }
    });
  }

  function escapeHtml(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }
  function escapeAttr(s) { return escapeHtml(s).replace(/`/g, '&#96;'); }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      try { init(); } catch (err) { console.error('[admin] init crashed:', err); }
    });
  } else {
    try { init(); } catch (err) { console.error('[admin] init crashed:', err); }
  }
})();
