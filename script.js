// Wait for the page to load
document.addEventListener('DOMContentLoaded', () => {
    
    const tableBody = document.getElementById('data-table-body');
    const pdfViewer = document.getElementById('pdf-viewer');
    const generateBtn = document.getElementById('generate-html-btn');
    const filterTopicInput = document.getElementById('filter-topic');

    let allData = []; // To store all parsed data from XML

    // 1. Fetch and Parse the XML data
    fetch('9702.xml')
        .then(response => response.text())
        .then(str => new window.DOMParser().parseFromString(str, "text/xml"))
        .then(xmlData => {
            const dataElements = xmlData.getElementsByTagName('Data');
            
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
                    otherTopics: otherTopics.join(', ') // Join other topics with a comma
                });
            }
            // Initial render of the table
            renderTable(allData);
        });

    // 2. Function to render the table rows
    function renderTable(data) {
        tableBody.innerHTML = ''; // Clear existing table
        
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

            // ▼▼▼ THIS IS THE CORRECTED "CLICK-TO-VIEW" LOGIC ▼▼▼
            tr.addEventListener('click', () => {
                // Use the correct GitHub Pages URL, not raw.githubusercontent.com
                pdfViewer.src = `https://sialaichai.github.io/physics9702/pdfs/${rowData.filename}`;
            });
            // ▲▲▲ THIS WILL NOW WORK AS A SPLIT-FORM ▲▲▲

            tableBody.appendChild(tr);
        }
    }
    
    // 4. Add filtering logic
    filterTopicInput.addEventListener('keyup', () => {
        const filterValue = filterTopicInput.value.toLowerCase();
        
        const filteredData = allData.filter(item => 
            item.mainTopic.toLowerCase().includes(filterValue) ||
            item.otherTopics.toLowerCase().includes(filterValue) ||
            item.filename.toLowerCase().includes(filterValue)
        );
        
        renderTable(filteredData);
    });

    // 5. Logic for the "Create HTML" button (This part is unchanged)
    generateBtn.addEventListener('click', () => {
        const visibleRows = tableBody.querySelectorAll('tr');
        
        // Use the GitHub Pages URL here as well
        const pdfBaseUrl = "https://sialaichai.github.io/physics9702/pdfs/";

        let htmlContent = `
            <!DOCTYPE html>
            <html lang='en'>
            <head>
              <meta charset='UTF-8'>
              <title>Filtered PDF Report</title>
              <style>
                body { font-family: 'Segoe UI', Tahoma, sans-serif; margin: 20px; background: #f4f4f4; }
                h1 { text-align: center; color: #333; }
                .pdf-section { 
                    margin-bottom: 40px; 
                    background: #ffffff; 
                    padding: 15px; 
                    border-radius: 8px; 
                    box-shadow: 0 2px 5px rgba(0,0,0,0.1); 
                }
                .header-row { 
                    font-size: 1.2em; 
                    margin-bottom: 10px; 
                    padding-bottom: 5px;
                    border-bottom: 1px solid #eee;
                }
                .file-title { font-weight: bold; }
                .topic-label { color: #555; }
                embed { 
                    width: 100%; 
                    height: 800px; 
                    border: 1px solid #ccc;
                    border-radius: 4px;
                }
              </style>
            </head>
            <body>
                <h1>Filtered PDF Report</h1>
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
                    <embed 
                        src='${fullPdfUrl}' 
                        type='application/pdf'
                    />
                </div>
            `;
        });

        htmlContent += `
            </body>
            </html>
        `;

        // Create a file in-memory and trigger a download
        const blob = new Blob([htmlContent], { type: 'text/html' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'filtered_report.html';
        a.click();
        URL.revokeObjectURL(a.href);
    });

});
