'use strict';

const $ = id => document.getElementById(id);
let csrf = '';
let current = null;
let refreshTask = null;
let filter = 'all';
let domainDirty = false;
let adminDirty = false;
let listSignature = '';
let toastTimer;
let connectingClient = null;
let connectionView = 0;
let confirmResolve = null;

async function request(path, method = 'GET', body) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 40000);
  try {
    const response = await fetch(path, {
      method,
      signal: controller.signal,
      credentials: 'same-origin',
      headers: {
        'Content-Type': 'application/json',
        ...(csrf ? { 'X-CSRF-Token': csrf } : {})
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) })
    });
    const data = await response.json();
    if (!response.ok) {
      if (response.status === 401 && path !== '/api/login') showLogin();
      throw new Error(data.error || '操作失败，请重试。');
    }
    return data;
  } catch (error) {
    if (error.name === 'AbortError') throw new Error('请求超时，请刷新确认结果。');
    if (error instanceof TypeError) throw new Error('网络连接中断，请重试。');
    throw error;
  } finally {
    clearTimeout(timeout);
  }
}

function globalError(message) {
  $('global-error').textContent = message;
  $('global-error').hidden = !message;
}

function showLogin() {
  document.querySelectorAll('dialog[open]').forEach(dialog => dialog.close());
  $('boot-view').hidden = true;
  $('login-view').hidden = false;
  $('app-view').hidden = true;
  $('username').value = '';
  $('password').value = '';
  clearAdminForm();
  csrf = '';
  current = null;
  domainDirty = false;
  listSignature = '';
}

function toast(message) {
  $('toast').textContent = message;
  $('toast').hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { $('toast').hidden = true; }, 2500);
}

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function navigate(page) {
  if (page !== 'administrator') clearAdminForm();
  else if (!adminDirty && current?.administrator) $('admin-username').value = current.administrator.username;
  document.querySelectorAll('.page').forEach(node => {
    node.hidden = node.id !== `page-${page}`;
  });
  document.querySelectorAll('[data-page]').forEach(node => {
    const selected = node.dataset.page === page;
    node.classList.toggle('active', selected);
    node.setAttribute('aria-current', selected ? 'page' : 'false');
  });
}

function selectFilter(value) {
  filter = value;
  $('client-list-scroll').scrollTop = 0;
  document.querySelectorAll('[data-filter]').forEach(node => {
    const selected = node.dataset.filter === value;
    node.classList.toggle('selected', selected);
    node.setAttribute('aria-pressed', String(selected));
  });
  renderClients();
}

function statusOf(client) {
  if (!client.exists || !client.enabled) return 'error';
  const age = Date.now() - Date.parse(client.lastHandshake);
  return client.lastHandshake && age >= -60000 && age < 180000 ? 'online' : 'offline';
}

function showHelp(client) {
  connectingClient = client.id;
  connectionView++;
  $('help-title').textContent = `连接 ${client.name}`;
  $('connect-endpoint').value = `https://${current.settings.sipDomain || current.publicIp}/api/connect`;
  $('connect-token').value = '';
  $('copy-token').disabled = true;
  $('generate-token').disabled = false;
  $('generate-token').textContent = '生成接入码';
  $('connect-error').textContent = '';
  $('help-dialog').showModal();
}

async function generateToken() {
  const clientId = connectingClient;
  const view = connectionView;
  if (clientId === null) return;
  $('generate-token').disabled = true;
  $('connect-error').textContent = '';
  try {
    const result = await request(`/api/clients/${clientId}/enrollment`, 'POST', {});
    if (view !== connectionView) return;
    $('connect-endpoint').value = result.endpoint;
    $('connect-token').value = result.token;
    $('copy-token').disabled = false;
    $('generate-token').textContent = '生成新的';
  } catch (error) {
    if (view === connectionView) $('connect-error').textContent = error.message;
  } finally {
    if (view === connectionView) $('generate-token').disabled = false;
  }
}

async function copyField(id) {
  try { await navigator.clipboard.writeText($(id).value); toast('已复制'); }
  catch { $('connect-error').textContent = '复制失败，请检查浏览器剪贴板权限。'; }
}

function confirmAction(title, message) {
  if (confirmResolve) return Promise.resolve(false);
  $('confirm-title').textContent = title;
  $('confirm-message').textContent = message;
  const dialog = $('confirm-dialog');
  dialog.returnValue = '';
  const answer = new Promise(resolve => { confirmResolve = resolve; });
  dialog.showModal();
  $('confirm-cancel').focus();
  return answer;
}

$('confirm-accept').addEventListener('click', () => $('confirm-dialog').close('confirm'));
$('confirm-dialog').addEventListener('close', () => {
  const resolve = confirmResolve;
  confirmResolve = null;
  if (resolve) resolve($('confirm-dialog').returnValue === 'confirm');
});

function validateForm(form, errorId) {
  $(errorId).textContent = '';
  const field = Array.from(form.elements).find(input => input.willValidate && !input.validity.valid);
  if (!field) return true;
  const name = field.getAttribute('aria-label') || field.labels?.[0]?.textContent.trim() || '内容';
  const validity = field.validity;
  let message = `请检查${name}`;
  if (validity.valueMissing) message = `请填写${name}`;
  else if (validity.tooShort) message = `${name}至少 ${field.minLength} 位`;
  else if (validity.tooLong) message = `${name}最多 ${field.maxLength} 位`;
  else if (validity.rangeUnderflow || validity.rangeOverflow) message = `${name}范围为 ${field.min}–${field.max}`;
  else if (validity.badInput || validity.stepMismatch) message = `${name}请输入有效整数`;
  $(errorId).textContent = message;
  field.setAttribute('aria-invalid', 'true');
  field.focus();
  return false;
}

document.querySelectorAll('form').forEach(form => {
  form.addEventListener('input', event => event.target.removeAttribute('aria-invalid'));
});

async function removeClient(client, button) {
  if (button.disabled) return;
  button.disabled = true;
  try {
    if (!await confirmAction(`删除「${client.name}」？`, `连接密钥和 ${client.start}–${client.end} 端口转发将撤销。`)) return;
    await request(`/api/clients/${client.id}`, 'DELETE');
    await refresh();
    toast('已删除');
  } catch (error) {
    globalError(error.message);
  } finally {
    button.disabled = false;
  }
}

function clientRow(client) {
  const row = element('tr');
  row.append(
    element('td', client.name, 'client-name'),
    element('td', client.ip, 'mono'),
    element('td', `${client.start} – ${client.end}`, 'mono')
  );
  const state = statusOf(client);
  const color = state === 'online' ? 'green' : state === 'error' ? 'orange' : 'gray';
  const label = state === 'online' ? '已连接' : state === 'error'
    ? (!client.exists ? '配置缺失' : '已停用') : '未连接';
  const status = element('span', undefined, `status ${state}`);
  status.append(element('i', undefined, `dot ${color}-dot`), element('span', label));
  const statusCell = element('td');
  statusCell.append(status);
  row.append(statusCell);

  const actions = element('div', undefined, 'client-actions');
  const help = element('button', '连接');
  help.addEventListener('click', () => showHelp(client));
  const remove = element('button', '删除', 'delete');
  remove.addEventListener('click', () => removeClient(client, remove));
  actions.append(help, remove);
  const actionCell = element('td');
  actionCell.append(actions);
  row.append(actionCell);
  return row;
}

function renderClients() {
  if (!current) return;
  const query = $('search').value.trim().toLocaleLowerCase();
  // Keep unchanged rows and keyboard focus intact during status refresh.
  const signature = JSON.stringify([filter, query, current.clients.map(client => [
    client.id, client.name, client.ip, client.start, client.end,
    client.exists, client.enabled, statusOf(client)
  ])]);
  if (signature === listSignature) return;
  listSignature = signature;

  const connected = current.clients.filter(client => statusOf(client) === 'online').length;
  $('stat-all').textContent = current.clients.length;
  $('stat-online').textContent = connected;
  $('stat-offline').textContent = current.clients.length - connected;
  const visible = current.clients.filter(client => {
    const matchesStatus = filter === 'all' || (filter === 'online'
      ? statusOf(client) === 'online' : statusOf(client) !== 'online');
    const text = `${client.name} ${client.ip} ${client.start} ${client.end}`.toLocaleLowerCase();
    return matchesStatus && text.includes(query);
  });
  const rows = document.createDocumentFragment();
  visible.forEach(client => rows.append(clientRow(client)));
  $('clients').replaceChildren(rows);
  $('empty').hidden = visible.length !== 0;
  $('empty-title').textContent = current.clients.length ? '没有匹配结果' : '暂无客户端';
  $('table-count').textContent = visible.length === current.clients.length
    ? `${current.clients.length} 个客户端` : `${visible.length} / ${current.clients.length} 个客户端`;
}

function render(data) {
  current = data;
  csrf = data.csrf;
  $('boot-view').hidden = true;
  $('login-view').hidden = true;
  $('app-view').hidden = false;
  $('sidebar-ip').textContent = data.publicIp;
  $('settings-ip').textContent = data.publicIp;
  if (!adminDirty && data.administrator) $('admin-username').value = data.administrator.username;
  if (!domainDirty) {
    $('sip-domain').value = data.settings.sipDomain;
    $('panel-domain').value = data.settings.panelDomain;
  }
  renderClients();
}

function refresh() {
  if (refreshTask) return refreshTask;
  refreshTask = request('/api/state').then(data => {
    render(data);
    globalError('');
  }).finally(() => { refreshTask = null; });
  return refreshTask;
}

$('login-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (!validateForm(event.target, 'login-error')) return;
  const button = event.target.querySelector('button');
  button.disabled = true;
  $('login-error').textContent = '';
  try {
    const result = await request('/api/login', 'POST', {
      username: $('username').value, password: $('password').value
    });
    csrf = result.csrf;
    $('password').value = '';
    navigate('clients');
    await refresh();
  } catch (error) {
    $('login-error').textContent = error.message;
  } finally {
    button.disabled = false;
  }
});

$('create-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (!validateForm(event.target, 'form-error')) return;
  $('create-button').disabled = true;
  $('create-button').textContent = '创建中…';
  $('form-error').textContent = '';
  try {
    const result = await request('/api/clients', 'POST', {
      name: $('client-name').value.trim(),
      start: Number($('port-start').value), end: Number($('port-end').value)
    });
    event.target.reset();
    $('create-dialog').close();
    $('search').value = '';
    selectFilter('all');
    showHelp(result.client);
    toast('已创建');
    await refresh().catch(error => globalError(error.message));
  } catch (error) {
    $('form-error').textContent = error.message;
  } finally {
    $('create-button').disabled = false;
    $('create-button').textContent = '创建';
  }
});

async function domains(save) {
  if (!validateForm($('domain-form'), 'domain-message')) return;
  $('check-dns').disabled = true;
  $('save-domains').disabled = true;
  $('domain-message').textContent = '检查中…';
  try {
    const result = await request(save ? '/api/settings' : '/api/settings/check', 'POST', {
      sipDomain: $('sip-domain').value.trim(), panelDomain: $('panel-domain').value.trim()
    });
    if (save) {
      domainDirty = false;
      await refresh();
      $('domain-message').textContent = result.settings.panelDomain
        ? '已保存。证书签发中可继续通过 IP 访问。' : '已保存';
    } else {
      $('domain-message').textContent = Object.entries(result.checks).map(([key, value]) => {
        const label = key === 'sipDomain' ? 'SIP 域名' : '面板域名';
        const message = !value.domain ? '使用 IP' : value.mode === 'cloudflare' ? '已识别 Cloudflare 代理，回源待验证' : value.ok ? '解析正常'
          : `解析不匹配（${value.addresses.join(', ') || '无记录'}）`;
        return `${label}：${message}`;
      }).join('\n');
    }
  } catch (error) {
    $('domain-message').textContent = error.message;
  } finally {
    $('check-dns').disabled = false;
    $('save-domains').disabled = false;
  }
}

function clearAdminForm() {
  $('admin-form').reset();
  $('admin-error').textContent = '';
  adminDirty = false;
  document.querySelectorAll('[data-password]').forEach(button => {
    $(button.dataset.password).type = 'password';
    button.setAttribute('aria-pressed', 'false');
    button.setAttribute('aria-label', `显示${document.querySelector(`label[for="${button.dataset.password}"]`).textContent}`);
  });
}

$('admin-form').addEventListener('input', () => { adminDirty = true; $('admin-error').textContent = ''; });
$('admin-form').addEventListener('submit', async event => {
  event.preventDefault();
  if (!validateForm(event.target, 'admin-error')) return;
  $('save-admin').disabled = true;
  $('admin-error').textContent = '';
  try {
    const result = await request('/api/admin/profile', 'POST', {
      username: $('admin-username').value.trim(),
      currentPassword: $('admin-current').value,
      newPassword: $('admin-new').value,
      confirmPassword: $('admin-confirm').value
    });
    if (result.changed) {
      showLogin();
      toast('已保存，请重新登录');
    } else {
      clearAdminForm();
      if (current?.administrator) $('admin-username').value = current.administrator.username;
      toast('没有需要修改的内容');
    }
  } catch (error) {
    $('admin-error').textContent = error.message;
  } finally {
    $('save-admin').disabled = false;
  }
});
document.querySelectorAll('[data-password]').forEach(button => {
  button.addEventListener('click', () => {
    const input = $(button.dataset.password);
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    button.setAttribute('aria-pressed', String(show));
    const label = document.querySelector(`label[for="${input.id}"]`).textContent;
    button.setAttribute('aria-label', `${show ? '隐藏' : '显示'}${label}`);
  });
});

$('open-create').addEventListener('click', () => {
  $('form-error').textContent = '';
  $('create-dialog').showModal();
});
$('logout').addEventListener('click', async () => {
  try { await request('/api/logout', 'POST', {}); showLogin(); }
  catch (error) { globalError(error.message); }
});
$('search').addEventListener('input', () => {
  $('client-list-scroll').scrollTop = 0;
  renderClients();
});
$('generate-token').addEventListener('click', generateToken);
$('copy-endpoint').addEventListener('click', () => copyField('connect-endpoint'));
$('copy-token').addEventListener('click', () => copyField('connect-token'));
$('help-dialog').addEventListener('close', () => {
  connectionView++;
  connectingClient = null;
  $('connect-token').value = '';
});
$('domain-form').addEventListener('input', () => {
  domainDirty = true;
  $('domain-message').textContent = '';
});
$('check-dns').addEventListener('click', () => domains(false));
$('domain-form').addEventListener('submit', event => {
  event.preventDefault();
  domains(true);
});
document.querySelectorAll('[data-filter]').forEach(node => {
  node.addEventListener('click', () => selectFilter(node.dataset.filter));
});
document.querySelectorAll('[data-page]').forEach(node => {
  node.addEventListener('click', () => navigate(node.dataset.page));
});
document.querySelectorAll('[data-close]').forEach(node => {
  node.addEventListener('click', () => $(node.dataset.close).close());
});

async function loadPage() {
  $('boot-message').textContent = '载入中…';
  $('boot-retry').hidden = true;
  try { await refresh(); }
  catch (error) {
    if (!$('login-view').hidden) return;
    $('boot-message').textContent = error.message;
    $('boot-retry').hidden = false;
  }
}
$('boot-retry').addEventListener('click', loadPage);
loadPage();
setInterval(() => {
  if (!$('app-view').hidden && !$('page-clients').hidden && !document.hidden
      && !document.querySelector('dialog[open]')) {
    refresh().catch(error => globalError(error.message));
  }
}, 30000);
