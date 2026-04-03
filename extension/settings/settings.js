document.addEventListener('DOMContentLoaded', () => {
    const input = document.getElementById('apiUrlInput');
    const saveBtn = document.getElementById('saveBtn');
    const savedMsg = document.getElementById('savedMsg');

    // Load saved URL
    chrome.storage.sync.get(['apiUrl'], (result) => {
        input.value = result.apiUrl || 'http://localhost:8000';
    });

    // Save
    saveBtn.addEventListener('click', () => {
        const url = input.value.trim().replace(/\/+$/, ''); // Remove trailing slashes
        chrome.storage.sync.set({ apiUrl: url }, () => {
            savedMsg.classList.add('show');
            setTimeout(() => savedMsg.classList.remove('show'), 2000);
        });
    });
});
