document.addEventListener('DOMContentLoaded', () => {
    
    // Get references to all interactive elements
    const tableBody = document.getElementById('data-table-body');
    const pdfViewer = document.getElementById('pdf-viewer');
    const generateBtn = document.getElementById('generate-html-btn');
    
    // Get references to the drop-down filters
    const topicFilter = document.getElementById('filter-topic');
    const yearFilter = document.getElementById('filter-year');
    const paperFilter = document.getElementById('filter-paper');
    const questionFilter = document.getElementById('filter-question');

    let allData = []; // To store all parsed data from XML

    // 1. Fetch and Parse the XML data
    fetch('9702.xml') // This fetch might be failing silently
        .then(response => {
            if (!response.ok) {
                // This will trigger if 9702.xml is not found (e.g., 404 error)
                throw new Error(`Failed to fetch 9702.xml - Status: ${response.status}`);
            }
            return response.text();
        })
        .then(str => new window.DOMParser().parseFromString(str, "text/xml"))
        .then(xmlData => {
            // Check if the XML file itself has a parsing error
            if (xmlData.getElementsByTagName('parsererror').length > 0) {
                throw new Error('Failed to parse 9702.xml. The XML file may be corrupt.');
            }

            const dataElements = xmlData.getElementsByTagName('Data');
            
            // Check if any <Data> elements were found
            if (dataElements.length === 0) {
                throw new Error('XML file was loaded, but no <Data> elements were found inside it.');
            }

            for (const item of dataElements) {
                // Extract all categories
                let otherTopics = [];
                for (let i = 1; i <= 5; i++) {
                    const topicNode = item.getElementsByTagName(`Other_x0020_Topic_x0020_Category_x0020_${i}`)[0];
                    if (topicNode) {
                        otherTopics.push(topicNode.textContent);
                    }
                }

                // Store data as an object
                allData.push({
                    filename: item.getElementsByTagName('Filename')[0].textContent,
                    year: item.getElementsByTagName('Year')[0].textContent,
                    paper: item.getElementsByTagName('Paper')[0].textContent,
                    question: item.getElementsByTagName('Question')[0].textContent,
                    mainTopic: item.getElementsByTagName('Topic_x0020_Category')[0].textContent,
                    otherTopics: otherTopics.join(', ')
                });
            }

            // If we get here, data is loaded and parsed!
            populateDropdowns();
            
            // Add event listeners to the filters
            topicFilter.addEventListener('change', applyFilters);
            yearFilter.addEventListener('change', applyFilters);
            paperFilter.addEventListener('change', applyFilters);
            questionFilter.addEventListener('change', applyFilters);

            // Initial render of the table
            renderTable(allData);
        })
        .catch(error => {
            // ▼▼▼ THIS IS THE NEW ERROR CATCHER ▼▼▼
            // If any of the steps above fail, this alert will show you the problem.
            console.error('Error details:', error);
            alert('A critical error occurred:\n\n' + error.message + 
                  '\n\nThis is why the dropdowns are blank. Please ensure 9702.xml is in the same folder as index.html.');
        });

    // 2. Function to populate the drop-down lists
    function populateDropdowns() {
        // Use Sets to get unique values
        const topics = [...new Set(allData.map(item => item.mainTopic))].sort();
        const years = [...new Set(allData.map(item => item.year))].sort((a, b) => b - a); // Sort years descending
        const papers = [...new Set(allData.map(item => item.paper))].sort();
        const questions = [...new Set(allData.map(item => item.question))].sort();

        // Helper function to add options to a select
        const addOptions = (selectElement, options, defaultText) => {
            if (!selectElement) {
                console.error(`Error: The element for "${defaultText}" was not found.`);
                return; // Stop if the HTML element doesn't exist
            }
            selectElement.innerHTML = `<option value="all">All ${defaultText}</option>`; // Clear and add default
            options.forEach(optionValue => {
                const option = document.createElement('option');
                option.value = optionValue;
                option.text = optionValue;
                selectElement.appendChild(option);
            });
        };

        // Populate each drop-down
        addOptions(topicFilter, topics, 'Topics');
        addOptions(yearFilter, years, 'Years');
        addOptions(paperFilter, papers, 'Papers');
        addOptions(questionFilter, questions, 'Questions');
    }

    // 3. Function to filter data based on all drop-downs
    function applyFilters() {
        const selectedTopic = topicFilter.value;
        const selectedYear = yearFilter.value;
        const selectedPaper = paperFilter.value;
        const selectedQuestion = questionFilter.value;

        let filteredData = allData;

        // Apply filters one by one
        if (selectedTopic !== 'all') {
            filteredData = filteredData.filter(item => item.mainTopic === selectedTopic);
        }
        if (selectedYear !== 'all') {
            filteredData = filteredData.filter(item => item.year === selectedYear);
        }
        if (selectedPaper !== 'all') {
            filteredData = filteredData.filter(item => item.paper === selectedPaper);
        }
        if (selectedQuestion !== 'all') {
            filteredData = filteredData.filter(item => item.question === selectedQuestion);
        }

        renderTable(filteredData);
    }

    // 4. Function to render the table rows
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
                <td>${rowData.otherTopics}</td>
            `;
            tr.addEventListener('click', () => {
                pdfViewer.src = `https://sialaichai.github.io/physics9702/pdfs/${rowData.filename}`;
            });
            tableBody.appendChild(tr);
        }
    }
    
    // 5. Logic for the "Create HTML" button
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
            const mainTopic = row.cells[4].textContent;
            const fullPdfUrl = pdfBaseUrl + filename;
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
});
