async function send(type, payload = {}) {
  return chrome.runtime.sendMessage({ type, ...payload });
}

function setMessage(text, isError = false) {
  const saved = document.getElementById('saved');
  saved.textContent = text;
  saved.style.color = isError ? '#ff7283' : '';
  if (!isError) setTimeout(() => { saved.textContent = ''; }, 1800);
}

async function init() {
  try {
    const r = await send('PD_GET_SETTINGS');
    const s = r.settings;
    for (const id of ['paused', 'mediumNotifications', 'highNotifications', 'criticalNotifications']) document.getElementById(id).checked = Boolean(s[id]);
    document.getElementById('medium').value = s.thresholds.medium;
    document.getElementById('high').value = s.thresholds.high;
    document.getElementById('critical').value = s.thresholds.critical;
  } catch (error) { setMessage(error.message || 'Unable to load settings.', true); }
}

document.getElementById('save').onclick = async () => {
  const medium = Number(document.getElementById('medium').value);
  const high = Number(document.getElementById('high').value);
  const critical = Number(document.getElementById('critical').value);
  if (![medium, high, critical].every(Number.isFinite) || medium < 0 || high < medium || critical < high || critical > 100) {
    setMessage('Use thresholds in ascending order: 0 ≤ medium ≤ high ≤ critical ≤ 100.', true);
    return;
  }
  const settings = {
    paused: document.getElementById('paused').checked,
    mediumNotifications: document.getElementById('mediumNotifications').checked,
    highNotifications: document.getElementById('highNotifications').checked,
    criticalNotifications: document.getElementById('criticalNotifications').checked,
    thresholds: { medium, high, critical }
  };
  try {
    const result = await send('PD_SAVE_SETTINGS', { settings });
    if (!result?.ok) throw new Error(result?.error || 'Unable to save settings.');
    setMessage('Saved');
  } catch (error) { setMessage(error.message || 'Unable to save settings.', true); }
};

void init();
