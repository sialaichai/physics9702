document.addEventListener('DOMContentLoaded', () => {
    
    // --- Get references to all interactive elements ---
    const tableBody = document.getElementById('data-table-body');
    const pdfViewer = document.getElementById('pdf-viewer');
    const generateBtn = document.getElementById('generate-html-btn');
    const fileCountDisplay = document.getElementById('file-count-display'); // <-- ADD THIS
    
    // Standard filters
    const questionFilter = document.getElementById('filter-question');

    // Topic Filter elements
    const topicFilterBtn = document.getElementById('topic-filter-btn');
    const topicFilterPanel = document.getElementById('topic-filter-panel');
    const topicFilterList = document.getElementById('topic-filter-list');
    const topicFilterApply = document.getElementById('topic-filter-apply');
    const topicFilterCount = document.getElementById('topic-filter-count');

    // Year Filter elements
    const yearFilterBtn = document.getElementById('year-filter-btn');
    const yearFilterPanel = document.getElementById('year-filter-panel');
    const yearFilterList = document.getElementById('year-filter-list');
    const yearFilterApply = document.getElementById('year-filter-apply');
    const yearFilterCount = document.getElementById('year-filter-count');

    // Paper Filter elements
    const paperFilterBtn = document.getElementById('paper-filter-btn');
    const paperFilterPanel = document.getElementById('paper-filter-panel');
    const paperFilterList = document.getElementById('paper-filter-list');
    const paperFilterApply = document.getElementById('paper-filter-apply');
    const paperFilterCount = document.getElementById('paper-filter-count');

    let allData = []; // To store all parsed data from XML
    
    // --- State for selected filters ---
    let selectedTopics = new Set();
    let selectedYears = new Set();
    let selectedPapers = new Set();

    // --- Helper function to safely get and trim text from XML ---
    function safeGetText(item, tagName) {
        const element = item.getElementsByTagName(tagName)[0];
        return element ? element.textContent.trim() : ''; 
    }

    // --- 1. Fetch and Parse the XML data ---
    fetch('9702.xml')
        .then(response => {
            if (!response.ok) throw new Error(`Failed to fetch 9702.xml - Status: ${response.status}`);
            return response.text();
        })
        .then(str => new window.DOMParser().parseFromString(str, "text/xml"))
        .then(xmlData => {
            if (xmlData.getElementsByTagName('parsererror').length > 0) {
                throw new Error('Failed to parse 9702.xml. The XML file may be corrupt.');
            }
            const dataElements = xmlData.getElementsByTagName('Data');
            if (dataElements.length === 0) throw new Error('XML file was loaded, but no <Data> elements were found.');

            for (const item of dataElements) {
                let otherTopics = [];
                for (let i = 1; i <= 5; i++) {
                    const topicText = safeGetText(item, `Other_x0020_Topic_x0020_Category_x0020_${i}`);
                    if (topicText) otherTopics.push(topicText);
                }
                allData.push({
                    filename: safeGetText(item, 'Filename'),
                    year: safeGetText(item, 'Year'),
                    paper: safeGetText(item, 'Paper'),
                    question: safeGetText(item, 'Question'),
                    mainTopic: safeGetText(item, 'Topic_x0020_Category'),
                    otherTopics: otherTopics
                });
            }

            populateDropdowns();
            setupEventListeners();
            renderTable(allData);
        })
        .catch(error => {
            console.error('Error details:', error);
            alert('A critical error occurred:\n\n' + error.message);
        });

    // --- 2. Populate Dropdowns AND Checkbox Lists ---
    function populateDropdowns() {
        
        // 1. Get ALL topic strings, including main and other
        const allTopicStrings = allData.flatMap(item => [item.mainTopic, ...item.otherTopics]);
        // 2. Split any strings that contain ";" or ",", then trim whitespace
        const allCleanTopics = allTopicStrings
            .flatMap(topicStr => topicStr.split(/[;,]/)) // Split by ; or ,
            .map(s => s.trim()); // Trim whitespace
        // 3. Now, get the unique, non-empty, sorted list from the CLEAN data
        const topics = [...new Set(allCleanTopics.filter(Boolean))].sort();

        // Get unique, filtered, sorted values (for other filters)
        const years = [...new Set(allData.map(item => item.year).filter(Boolean))].sort((a, b) => b - a); // Sort desc
        const papers = [...new Set(allData.map(item => item.paper).filter(Boolean))].sort();
        const questions = [...new Set(allData.map(item => item.question).filter(Boolean))].sort();

        // Helper: Add <option> to <select>
        const addOptions = (selectElement, options, defaultText) => {
            if (!selectElement) return;
            selectElement.innerHTML = `<option value="all">All ${defaultText}</option>`;
            options.forEach(optionValue => {
                const option = document.createElement('option');
                option.value = optionValue;
                option.text = optionValue;
                selectElement.appendChild(option);
            });
        };

        // Helper: Add Checkboxes to a list
        const addCheckboxes = (listElement, values, className) => {
            listElement.innerHTML = ''; // Clear list
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

        // Populate standard dropdown (Question)
        addOptions(questionFilter, questions, 'Questions');

        // Populate Checkbox Lists
        addCheckboxes(topicFilterList, topics, 'topic-checkbox');
        addCheckboxes(yearFilterList, years, 'year-checkbox');
        addCheckboxes(paperFilterList, papers, 'paper-checkbox');
    }
    
    // --- 3. Setup Event Listeners ---
    function setupEventListeners() {
        // Standard filter change
        questionFilter.addEventListener('change', applyFilters);

        // Helper function to manage a checkbox filter panel
        const setupFilterPanel = (btn, panel, list, applyBtn, selectedSet, countElement, checkboxClass) => {
            // Show/Hide Panel
            btn.addEventListener('click', () => {
                const isVisible = panel.style.display === 'block';
                panel.style.display = isVisible ? 'none' : 'block';
            });

            // Apply Filter
            applyBtn.addEventListener('click', () => {
                selectedSet.clear(); // Clear the set
                const checkedBoxes = list.querySelectorAll(`.${checkboxClass}:checked`);
                checkedBoxes.forEach(box => selectedSet.add(box.value));
                countElement.textContent = selectedSet.size; // Update count
                panel.style.display = 'none'; // Hide panel
                applyFilters(); // Run main filter
            });
        };

        // Setup all three checkbox filters
        setupFilterPanel(topicFilterBtn, topicFilterPanel, topicFilterList, topicFilterApply, selectedTopics, topicFilterCount, 'topic-checkbox');
        setupFilterPanel(yearFilterBtn, yearFilterPanel, yearFilterList, yearFilterApply, selectedYears, yearFilterCount, 'year-checkbox');
        setupFilterPanel(paperFilterBtn, paperFilterPanel, paperFilterList, paperFilterApply, selectedPapers, paperFilterCount, 'paper-checkbox');

        // Close panels if clicking outside
        document.addEventListener('click', (event) => {
            const panels = [topicFilterPanel, yearFilterPanel, paperFilterPanel];
            const buttons = [topicFilterBtn, yearFilterBtn, paperFilterBtn];

            // Check if the click is outside all panels and all buttons
            if (!panels.some(p => p.contains(event.target)) && !buttons.some(b => b.contains(event.target))) {
                panels.forEach(p => p.style.display = 'none');
            }
        });
    }

    // --- 4. Function to filter data based on all filters ---
    function applyFilters() {
        const selectedQuestion = questionFilter.value;

        let filteredData = allData;

        // Apply Topic Filter
        if (selectedTopics.size > 0) {
            filteredData = filteredData.filter(item => {
                // We must also split the data here to match
                const allItemTopics = [item.mainTopic, ...item.otherTopics]
                    .flatMap(topicStr => topicStr.split(/[;,]/))
                    .map(s => s.trim());

                for (const topic of allItemTopics) {
                    if (selectedTopics.has(topic)) {
                        return true;
                    }
                }
                return false;
            });
        }

        // Apply Year Filter
        if (selectedYears.size > 0) {
            filteredData = filteredData.filter(item => selectedYears.has(item.year));
        }

        // Apply Paper Filter
        if (selectedPapers.size > 0) {
            filteredData = filteredData.filter(item => selectedPapers.has(item.paper));
        }

        // Apply Question Filter
        if (selectedQuestion !== 'all') {
            filteredData = filteredData.filter(item => item.question === selectedQuestion);
        }

        renderTable(filteredData);
    }

    // --- 5. Function to render the table rows ---
    function renderTable(data) {
        tableBody.innerHTML = '';
        for (const rowData of data) {
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
                pdfViewer.src = `https://sialaichai.github.io/physics9702/pdfs/${rowData.year}/${rowData.filename}`;
            });
            tableBody.appendChild(tr);
        }
        // ▼▼▼ ADD THIS LINE ▼▼▼
        fileCountDisplay.textContent = `${data.length} files found`;
    }
    
    // --- 6. Logic for the "Create HTML" button ---
    generateBtn.addEventListener('click', () => {
        const visibleRows = tableBody.querySelectorAll('tr');
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
                        <span class='file-title'>${filename}</span>
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

    // --- 7. Draggable Resizer Logic ---
    const dragger = document.getElementById('dragger');
    const lowerPanel = document.getElementById('lower-panel');

    let isDragging = false;

    dragger.addEventListener('mousedown', (e) => {
        isDragging = true;
        // Add classes to prevent text selection/iframe issues while dragging
        document.body.style.userSelect = 'none';
        pdfViewer.style.pointerEvents = 'none';
    });

    document.addEventListener('mouseup', () => {
        isDragging = false;
        // Remove preventative styles
        document.body.style.userSelect = 'auto';
        pdfViewer.style.pointerEvents = 'auto';
    });

    document.addEventListener('mousemove', (e) => {
        if (!isDragging) return;

        // Calculate new height of the lower panel
        const newHeight = window.innerHeight - e.clientY - (dragger.offsetHeight / 2);

        // Get min/max heights
        const minHeight = 100; // Must match min-height in CSS
        const maxHeight = window.innerHeight - 150; // (window height) - (upper panel min-height)

        // Apply constraints
        if (newHeight > minHeight && newHeight < maxHeight) {
            lowerPanel.style.height = `${newHeight}px`;
        }
    });

}); // <-- This is the final closing parenthesis.
