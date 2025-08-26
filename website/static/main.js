function toggleDetails(ideaName) {
    const details = document.getElementById(ideaName + '-details');
    const button = document.querySelector(`button[aria-controls="${ideaName}-details"]`);
    const isExpanded = details.getAttribute('aria-hidden') === 'false';
    details.setAttribute('aria-hidden', isExpanded);
    button.setAttribute('aria-expanded', !isExpanded);
    details.style.display = isExpanded ? 'none' : 'block';
}

function updateTotalRaised() {
    fetch('/total-raised')
        .then(response => response.json())
        .then(data => {
            const totalRaisedElement = document.getElementById('total-raised-amount');
            if (totalRaisedElement) {
                totalRaisedElement.textContent = `$${data.total_raised.toLocaleString()}`;
            }
        })
        .catch(error => console.error('Error fetching total raised:', error));
}

// Update every 5 seconds
setInterval(updateTotalRaised, 5000);
updateTotalRaised(); // Initial update