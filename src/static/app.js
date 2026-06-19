// SigViewer web UI — upload a PDF, poll progress every 500 ms, render the
// opaque display tree returned by the server.

const openBtn = document.getElementById('openBtn');
const fileInput = document.getElementById('fileInput');
const validate = document.getElementById('validate');
const fileName = document.getElementById('fileName');
const tree = document.getElementById('tree');
const progressWrap = document.getElementById('progressWrap');
const progressLabel = document.getElementById('progressLabel');
const bar = document.getElementById('bar');

let pollTimer = null;

openBtn.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', () => {
  if (fileInput.files.length) upload(fileInput.files[0]);
});

function setBusy(label) {
  progressWrap.classList.add('on');
  progressLabel.textContent = label;
  bar.removeAttribute('value');           // indeterminate
}
function setDeterminate(done, total) {
  progressLabel.textContent = `Fetching trust lists… ${done} / ${total}`;
  bar.max = total; bar.value = done;
}
function hideProgress() { progressWrap.classList.remove('on'); }

function upload(file) {
  if (pollTimer) { clearInterval(pollTimer); pollTimer = null; }
  fileName.textContent = file.name;
  tree.innerHTML = '';
  setBusy('Uploading…');

  const fd = new FormData();
  fd.append('pdf', file);
  fd.append('validate', validate.checked ? 'true' : 'false');

  fetch('/analyze', { method: 'POST', body: fd })
    .then(r => r.ok ? r.json() : r.text().then(t => Promise.reject(t)))
    .then(({ job_id }) => poll(job_id))
    .catch(err => showError(String(err)));
}

function poll(jobId) {
  setBusy('Working…');
  pollTimer = setInterval(() => {
    fetch('/status/' + jobId)
      .then(r => r.ok ? r.json() : Promise.reject('status ' + r.status))
      .then(s => {
        if (s.state === 'running') {
          if (s.total > 0) setDeterminate(s.done, s.total);
          else setBusy('Working…');
        } else if (s.state === 'done') {
          clearInterval(pollTimer); pollTimer = null;
          hideProgress();
          renderTree(s.tree);
        } else if (s.state === 'error') {
          clearInterval(pollTimer); pollTimer = null;
          hideProgress();
          showError(s.error || 'Analysis failed.');
        }
      })
      .catch(err => { clearInterval(pollTimer); pollTimer = null;
                      hideProgress(); showError(String(err)); });
  }, 500);
}

function showError(msg) {
  tree.innerHTML = '';
  const d = document.createElement('div');
  d.className = 'empty error';
  d.textContent = msg;
  tree.appendChild(d);
}

// Render the opaque display tree. label is server-escaped (only <strong>/<em>),
// so innerHTML is safe. Indentation by depth mirrors the PyQt QTreeView.
function renderTree(nodes) {
  tree.innerHTML = '';
  if (!nodes || !nodes.length) {
    showError('No data.'); return;
  }
  const walk = (list, depth) => {
    for (const n of list) {
      const row = document.createElement('div');
      row.className = 'node' + (n.children ? ' branch' : ' leaf');
      row.style.paddingLeft = (12 + depth * 20) + 'px';
      row.innerHTML = n.label;
      tree.appendChild(row);
      if (n.children) walk(n.children, depth + 1);
    }
  };
  walk(nodes, 0);
}
