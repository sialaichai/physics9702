document.addEventListener('DOMContentLoaded', () => {

    // ======================================================
    // 1. PASSWORD PROTECTION
    // ======================================================
    const correctHash = "2112653932"; 

    function simpleHash(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash; 
        }
        return hash.toString();
    }

  
// inside script.js - replace the checkSessionAndLogin function

function checkSessionAndLogin() {
    // If logged in, SHOW the container
    if (sessionStorage.getItem('accessGranted') === 'true') {
        document.getElementById('main-container').style.display = 'flex';
        return; 
    }
    
    // If NOT logged in, the container is already hidden by HTML style="display:none"
    // Just show the password setup/modal
    if (correctHash === "") {
        const setupPass = prompt("SETUP MODE: Enter password to hash:");
        if (setupPass) alert(simpleHash(setupPass));
        return;
    }
    createLoginModal();
}


    
    function createLoginModal() {
        const overlay = document.createElement('div');
        overlay.id = 'login-overlay';
        Object.assign(overlay.style, {
            position: 'fixed', top: '0', left: '0', width: '100%', height: '100%',
            backgroundColor: 'rgba(0,0,0,0.85)', zIndex: '9999',
            display: 'flex', justifyContent: 'center', alignItems: 'center', flexDirection: 'column'
        });

        const box = document.createElement('div');
        Object.assign(box.style, {
            backgroundColor: 'white', padding: '30px', borderRadius: '8px',
            textAlign: 'center', boxShadow: '0 4px 15px rgba(0,0,0,0.3)', fontFamily: 'sans-serif'
        });

        const title = document.createElement('h2');
        title.innerText = "Restricted Access";
        title.style.marginTop = '0';

        const input = document.createElement('input');
        input.type = 'password'; 
        input.placeholder = "Enter Password";
        Object.assign(input.style, {
            padding: '10px', fontSize: '16px', width: '200px', margin: '15px 0',
            border: '1px solid #ccc', borderRadius: '4px'
        });

        const btn = document.createElement('button');
        btn.innerText = "Login";
        Object.assign(btn.style, {
            padding: '10px 20px', fontSize: '16px', backgroundColor: '#007bff', color: 'white',
            border: 'none', borderRadius: '4px', cursor: 'pointer'
        });

        const errorMsg = document.createElement('p');
        errorMsg.style.color = 'red';
        errorMsg.style.display = 'none';
        errorMsg.innerText = "Incorrect Password";

        box.appendChild(title);
        box.appendChild(input);
        box.appendChild(document.createElement('br'));
        box.appendChild(btn);
        box.appendChild(errorMsg);
        overlay.appendChild(box);
        document.body.appendChild(overlay);

        function attemptLogin() {
            if (simpleHash(input.value) === correctHash) {
                sessionStorage.setItem('accessGranted', 'true');
                document.body.removeChild(overlay); 
                document.getElementById('main-container').style.display = 'flex'; 
            } else {
                errorMsg.style.display = 'block';
                input.value = ''; 
                input.focus();
            }
        }

        btn.addEventListener('click', attemptLogin);
        input.addEventListener('keypress', (e) => { if (e.key === 'Enter') attemptLogin(); });
        input.focus();
    }

    checkSessionAndLogin();


    // ======================================================
    // 2. MAIN APPLICATION LOGIC
    // ======================================================

    const tableBody = document.getElementById('data-table-body');
    const pdfViewer = document.getElementById('pdf-viewer');
    const generateBtn = document.getElementById('generate-html-btn');
    const fileCountDisplay = document.getElementById('file-count-display');
    
    // --- Filter Elements ---
    const topicFilterBtn = document.getElementById('topic-filter-btn');
    const topicFilterPanel = document.getElementById('topic-filter-panel');
    const topicFilterList = document.getElementById('topic-filter-list');
    const topicFilterApply = document.getElementById('topic-filter-apply');
    const topicFilterCount = document.getElementById('topic-filter-count');

    const yearFilterBtn = document.getElementById('year-filter-btn');
    const yearFilterPanel = document.getElementById('year-filter-panel');
    const yearFilterList = document.getElementById('year-filter-list');
    const yearFilterApply = document.getElementById('year-filter-apply');
    const yearFilterCount = document.getElementById('year-filter-count');

    const paperFilterBtn = document.getElementById('paper-filter-btn');
    const paperFilterPanel = document.getElementById('paper-filter-panel');
    const paperFilterList = document.getElementById('paper-filter-list');
    const paperFilterApply = document.getElementById('paper-filter-apply');
    const paperFilterCount = document.getElementById('paper-filter-count');

    const questionFilterBtn = document.getElementById('question-filter-btn');
    const questionFilterPanel = document.getElementById('question-filter-panel');
    const questionFilterList = document.getElementById('question-filter-list');
    const questionFilterApply = document.getElementById('question-filter-apply');
    const questionFilterCount = document.getElementById('question-filter-count');


    let allData = [];
    
    // --- Filter States ---
    let selectedTopics = new Set();
    let selectedYears = new Set();
    let selectedPapers = new Set();
    let selectedQuestions = new Set(); 

    // --- 1. Fetch JSON ---
    fetch('9702Phy.json')
        .then(response => {
            if (!response.ok) throw new Error(`Failed to fetch 9702Phy.json - Status: ${response.status}`);
            return response.json();
        })
        .then(jsonData => {
            // --- 1b. CLEAN DATA ---
            allData = jsonData.map(item => {
                // Clean Question field
                let q = (item.question || '').trim();
                q = q.replace(/\.pdf$/i, '');
                q = q.replace(/^q0+(\d)/i, 'q$1'); 

                return {
                    filename: (item.filename || '').trim(),
                    year: (item.year || '').trim(),
                    // JC field ignored
                    paper: (item.paper || '').trim(),
                    question: q, 
                    mainTopic: (item.mainTopic || '').trim(),
                    otherTopics: Array.isArray(item.otherTopics) 
                        ? item.otherTopics.map(t => t.trim()).filter(t => t !== "") 
                        : []
                };
            });

            populateDropdowns();
            setupEventListeners();
            renderTable(allData);
        })
        .catch(error => {
            console.error('Error details:', error);
            alert('Error loading data:\n\n' + error.message);
        });

    // --- 2. Populate Dropdowns ---
    function populateDropdowns() {
        const allTopicStrings = allData.map(item => item.mainTopic);
        const allCleanTopics = allTopicStrings
            .map(topicStr => topicStr.split(/[;,]/))
            .reduce((acc, val) => acc.concat(val), [])
            .map(s => s.trim());
        const topics = [...new Set(allCleanTopics.filter(Boolean))].sort();

        // --- MODIFIED YEAR SORT LOGIC ---
        // Sorts mixed numeric/alphanumeric years (e.g., "24", "m24", "s21") descending
        const years = [...new Set(allData.map(item => item.year).filter(Boolean))].sort((a, b) => {
            // Extract numbers (e.g., "m24" -> 24)
            const numA = parseInt(a.replace(/\D/g, '')) || 0;
            const numB = parseInt(b.replace(/\D/g, '')) || 0;

            // Primary sort: Numerical Value Descending (Newer years first)
            if (numA !== numB) return numB - numA;

            // Secondary sort: Alphabetical Descending 
            // This puts 'w' (Winter) before 's' (Summer) before 'm' (March)
            return b.localeCompare(a);
        });

        const papers = [...new Set(allData.map(item => item.paper).filter(Boolean))].sort();
        const questions = [...new Set(allData.map(item => item.question).filter(Boolean))].sort(naturalSort);

        const addCheckboxes = (listElement, values, className) => {
            if (!listElement) return; 
            listElement.innerHTML = ''; 
            values.forEach(value => {
                const label = document.createElement('label');
                const checkbox = document.createElement('input');
                checkbox.type = 'checkbox';
                checkbox.className = className;
                checkbox.value = value;
                label.appendChild(checkbox);
                label.appendChild(document.createTextNode(' ' + value));
                listElement.appendChild(label);
            });
        };

        addCheckboxes(topicFilterList, topics, 'topic-checkbox');
        addCheckboxes(yearFilterList, years, 'year-checkbox');
        addCheckboxes(paperFilterList, papers, 'paper-checkbox');
        addCheckboxes(questionFilterList, questions, 'question-checkbox');
    }
    
    function naturalSort(a, b) {
        return a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' });
    }
    
    // --- 3. Setup Event Listeners ---
    function setupEventListeners() {
        
        const setupFilterPanel = (btn, panel, list, applyBtn, selectedSet, countElement, checkboxClass) => {
            if (!btn || !panel || !list || !applyBtn) return; 

            btn.addEventListener('click', () => {
                const isVisible = panel.style.display === 'block';
                panel.style.display = isVisible ? 'none' : 'block';
            });

            applyBtn.addEventListener('click', () => {
                selectedSet.clear(); 
                const checkedBoxes = list.querySelectorAll(`.${checkboxClass}:checked`);
                checkedBoxes.forEach(box => selectedSet.add(box.value));
                countElement.textContent = selectedSet.size; 
                panel.style.display = 'none'; 
                applyFilters(); 
            });
        };

        setupFilterPanel(topicFilterBtn, topicFilterPanel, topicFilterList, topicFilterApply, selectedTopics, topicFilterCount, 'topic-checkbox');
        setupFilterPanel(yearFilterBtn, yearFilterPanel, yearFilterList, yearFilterApply, selectedYears, yearFilterCount, 'year-checkbox');
        setupFilterPanel(paperFilterBtn, paperFilterPanel, paperFilterList, paperFilterApply, selectedPapers, paperFilterCount, 'paper-checkbox');
        setupFilterPanel(questionFilterBtn, questionFilterPanel, questionFilterList, questionFilterApply, selectedQuestions, questionFilterCount, 'question-checkbox');

        // Close panels when clicking outside
        document.addEventListener('click', (event) => {
            const panels = [topicFilterPanel, yearFilterPanel, paperFilterPanel, questionFilterPanel].filter(Boolean);
            const buttons = [topicFilterBtn, yearFilterBtn, paperFilterBtn, questionFilterBtn].filter(Boolean);
            
            if (!panels.some(p => p.contains(event.target)) && !buttons.some(b => b.contains(event.target))) {
                panels.forEach(p => p.style.display = 'none');
            }
        });
    }

    // --- 4. Filter Data ---
    function applyFilters() {
        let filteredData = allData;

        // 1. Topics
        if (selectedTopics.size > 0) {
            filteredData = filteredData.filter(item => {
                if (!item.mainTopic) return false;
                const itemTopics = item.mainTopic.split(/[;,]/).map(s => s.trim());
                return itemTopics.some(topic => selectedTopics.has(topic));
            });
        }

        // 2. Years
        if (selectedYears.size > 0) filteredData = filteredData.filter(item => selectedYears.has(item.year));
        // 3. Papers
        if (selectedPapers.size > 0) filteredData = filteredData.filter(item => selectedPapers.has(item.paper));
        // 4. Questions
        if (selectedQuestions.size > 0) filteredData = filteredData.filter(item => selectedQuestions.has(item.question));

        renderTable(filteredData);
    }

    // --- 5. Render Table ---
    function renderTable(data) {
        if (!tableBody) return;
        tableBody.innerHTML = '';
        const fragment = document.createDocumentFragment();
        
        const displayData = data.length > 500 ? data.slice(0, 500) : data; 

        for (const rowData of displayData) {
            const tr = document.createElement('tr');
            tr.innerHTML = `
                <td>${rowData.filename}</td>
                <td>${rowData.year}</td>
                <td>${rowData.paper}</td>
                <td>${rowData.question}</td>
                <td>${rowData.mainTopic}</td>
                <td>${rowData.otherTopics.join(', ')}</td>
            `;
            tr.addEventListener('click', () => {
                pdfViewer.src = `pdfs/${rowData.year}/${rowData.filename}`;
            });
            fragment.appendChild(tr);
        }
        tableBody.appendChild(fragment);
        
        if (fileCountDisplay) {
            if (data.length > 500) {
                fileCountDisplay.textContent = `Top 500 of ${data.length} files`;
            } else {
                fileCountDisplay.textContent = `${data.length} files found`;
            }
        }
    }
    
    // --- 6. Generate HTML Report ---
    if (generateBtn) {
        generateBtn.addEventListener('click', () => {
            const visibleRows = tableBody.querySelectorAll('tr');

            if (visibleRows.length > 100) {
                const userConfirmed = confirm(`Warning: Generating a report with ${visibleRows.length} files. Browser may not load properly. Continue?`);
                if (!userConfirmed) return; 
            }

            const pdfBaseUrl = "https://sialaichai.github.io/physics9702/pdfs/";
            let htmlContent = `
                <!DOCTYPE html><html lang='en'><head><meta charset='UTF-8'><title>Filtered PDF Report</title>
                <style>
                    body { font-family: 'Segoe UI', Tahoma, sans-serif; margin: 20px; background: #f4f4f4; }
                    h1 { text-align: center; color: #333; } .pdf-section { margin-bottom: 40px; background: #ffffff; padding: 15px; border-radius: 8px; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
                    .header-row { font-size: 1.2em; margin-bottom: 10px; padding-bottom: 5px; border-bottom: 1px solid #eee; }
                    .file-title { font-weight: bold; } .topic-label { color: #555; }
                    embed { width: 100%; height: 800px; border: 1px solid #ccc; border-radius: 4px; }
                </style></head><body><h1>Filtered PDF Report</h1>
            `;
            visibleRows.forEach(row => {
                const filename = row.cells[0].textContent;
                const year = row.cells[1].textContent;
                const mainTopic = row.cells[4].textContent; 
                const fullPdfUrl = `${pdfBaseUrl}${year}/${filename}`;
                
                htmlContent += `
                    <div class='pdf-section'>
                        <div class='header-row'>
                            <span class'file-title'>${filename}</span>
                            <span class='topic-label'>(Category: ${mainTopic})</span>
                        </div>
                        <embed src='${fullPdfUrl}' type='application/pdf' />
                    </div>
                `;
            });
            htmlContent += `</body></html>`;
            const blob = new Blob([htmlContent], { type: 'text/html' });
            const a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = 'filtered_report.html';
            a.click();
            URL.revokeObjectURL(a.href);
        });
    }

    // --- 7. Draggable Resizer ---
    const dragger = document.getElementById('dragger');
    const lowerPanel = document.getElementById('lower-panel');
    if (dragger && lowerPanel) {
        let isDragging = false;
        dragger.addEventListener('mousedown', () => { isDragging = true; document.body.style.userSelect = 'none'; if (pdfViewer) pdfViewer.style.pointerEvents = 'none'; });
        document.addEventListener('mouseup', () => { isDragging = false; document.body.style.userSelect = 'auto'; if (pdfViewer) pdfViewer.style.pointerEvents = 'auto'; });
        document.addEventListener('mousemove', (e) => {
            if (!isDragging) return;
            const newHeight = window.innerHeight - e.clientY - (dragger.offsetHeight / 2);
            if (newHeight > 100 && newHeight < window.innerHeight - 150) {
                lowerPanel.style.height = `${newHeight}px`;
            }
        });
    }
});
