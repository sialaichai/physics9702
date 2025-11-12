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

            // 3. Add click event to row to show PDF
            tr.addEventListener('click', () => {
                // Assumes PDFs are in a 'pdfs' folder!
                pdfViewer.src = `pdfs/${rowData.filename}`;
            });

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

    // 5. Logic for the "Create HTML" button
    generateBtn.addEventListener('click', () => {
        // Get the *currently visible* (filtered) rows from the table
        const visibleRows = tableBody.querySelectorAll('tr');
        
        let htmlContent = `
            <html>
            <head><title>Filtered PDF List</title></head>
            <body>
                <h1>Filtered PDF List</h1>
                <ul>
        `;

        visibleRows.forEach(row => {
            const filename = row.cells[0].textContent; // Get filename from first cell
            // Assuming the PDFs are in the 'pdfs' folder in your repo
            htmlContent += `<li><a href="pdfs/${filename}">${filename}</a></li>\n`;
        });

        htmlContent += `
                </ul>
            </body>
            </html>
        `;

        // Create a file in-memory and trigger a download
        const blob = new Blob([htmlContent], { type: 'text/html' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'filtered_list.html'; // The suggested filename
        a.click();
        URL.revokeObjectURL(a.href);
    });

});
