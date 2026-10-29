interface ScanResult {
  path: string;
  hash: string;
  verdict: 'clean' | 'malicious' | 'suspicious' | 'unknown' | 'error';
}

interface ScanProgress {
  current: number;
  total: number;
  file: string;
}

let scanResults: ScanResult[] = [];
let isScanning = false;

// DOM elements
const dropZone = document.getElementById('drop-zone') as HTMLDivElement;
const fileInput = document.getElementById('file-input') as HTMLInputElement;
const folderInput = document.getElementById('folder-input') as HTMLInputElement;
const progressContainer = document.getElementById('progress-container') as HTMLDivElement;
const progressFill = document.getElementById('progress-fill') as HTMLDivElement;
const progressText = document.getElementById('progress-text') as HTMLParagraphElement;
const resultsTable = document.getElementById('results-table') as HTMLTableElement;
const resultsBody = document.getElementById('results-body') as HTMLTableSectionElement;
const emptyState = document.getElementById('empty-state') as HTMLDivElement;

// Drag & drop
dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  dropZone.classList.add('drag-over');
});

dropZone.addEventListener('dragleave', () => {
  dropZone.classList.remove('drag-over');
});

dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  dropZone.classList.remove('drag-over');
  if (e.dataTransfer.files.length > 0) {
    handleFiles(Array.from(e.dataTransfer.files));
  }
});

dropZone.addEventListener('click', () => {
  fileInput.click();
});

fileInput.addEventListener('change', (e) => {
  if (e.target.files && e.target.files.length > 0) {
    handleFiles(Array.from(e.target.files));
  }
});

// Folder scan button
document.getElementById('scan-folder-btn')?.addEventListener('click', () => {
  folderInput.click();
});

folderInput.addEventListener('change', async (e) => {
  if (e.target.files && e.target.files.length > 0) {
    // For folder, we use the first file's path to get directory
    const file = e.target.files[0];
    const path = file.webkitRelativePath ? file.webkitRelativePath.split('/')[0] : file.name;
    await scanDirectory(path);
  }
});

async function handleFiles(files: File[]) {
  if (isScanning) return;
  isScanning = true;
  showProgress(true);
  scanResults = [];

  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    updateProgress(i + 1, files.length, file.name);
    const result = await scanFile(file);
    scanResults.push(result);
    renderResults();
  }

  isScanning = false;
  showProgress(false);
}

async function scanDirectory(dirPath: string) {
  if (isScanning) return;
  isScanning = true;
  showProgress(true);
  scanResults = [];

  try {
    // This will invoke the Rust command
    const results = await window.__TAURI__.invoke('scan_directory', { dir: dirPath });
    scanResults = results as ScanResult[];
    renderResults();
  } catch (err) {
    console.error('Scan failed:', err);
    scanResults = [{
      path: dirPath,
      hash: '',
      verdict: 'error'
    }];
    renderResults();
  }

  isScanning = false;
  showProgress(false);
}

async function scanFile(file: File): Promise<ScanResult> {
  try {
    // Create a temporary file path for the Rust side to read
    // In real app, you'd use the FS plugin to write to temp and scan
    const result = await window.__TAURI__.invoke('scan_file', { path: file.name });
    return result as ScanResult;
  } catch (err) {
    return {
      path: file.name,
      hash: '',
      verdict: 'error'
    };
  }
}

function updateProgress(current: number, total: number, file: string) {
  const percent = Math.round((current / total) * 100);
  progressFill.style.width = `${percent}%`;
  progressText.textContent = `Scanning ${current}/${total}: ${file}`;
}

function showProgress(show: boolean) {
  progressContainer.classList.toggle('visible', show);
  resultsTable.classList.toggle('visible', !show && scanResults.length > 0);
  emptyState.classList.toggle('visible', !show && scanResults.length === 0);
}

function renderResults() {
  if (scanResults.length === 0) {
    resultsTable.classList.remove('visible');
    emptyState.classList.add('visible');
    return;
  }

  resultsTable.classList.add('visible');
  emptyState.classList.remove('visible');

  resultsBody.innerHTML = scanResults.map(r => `
    <tr>
      <td class="path-cell" title="${r.path}">${r.path}</td>
      <td class="hash-cell">${r.hash.slice(0, 16)}...</td>
      <td><span class="verdict ${r.verdict}">${r.verdict}</span></td>
    </tr>
  `).join('');
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  showProgress(false);
});