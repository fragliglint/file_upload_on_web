// Enhanced user experience for file storage app

document.addEventListener('DOMContentLoaded', function () {
    // Show selected file name in the upload form
    const fileInput = document.getElementById('userfile');
    if (fileInput) {
        fileInput.addEventListener('change', function () {
            if (fileInput.files.length > 0) {
                let label = document.getElementById('file-preview-label');
                if (!label) {
                    label = document.createElement('div');
                    label.id = 'file-preview-label';
                    label.style.marginTop = '8px';
                    label.style.fontSize = '14px';
                    label.style.color = '#34495e';
                    fileInput.parentNode.insertBefore(label, fileInput.nextSibling);
                }
                label.textContent = "Selected: " + fileInput.files[0].name;
            }
        });
    }

    // Prevent double form submission and show loading spinner
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function (e) {
            // Prevent double submit
            if (form.classList.contains('submitted')) {
                e.preventDefault();
                return false;
            }
            form.classList.add('submitted');

            // Remove any existing spinner
            const oldSpinner = document.getElementById('form-spinner');
            if (oldSpinner) oldSpinner.remove();

            // Show loading spinner
            let spinner = document.createElement('div');
            spinner.className = 'spinner';
            spinner.style.margin = '15px auto';
            spinner.style.border = '4px solid #f3f3f3';
            spinner.style.borderTop = '4px solid #3498db';
            spinner.style.borderRadius = '50%';
            spinner.style.width = '32px';
            spinner.style.height = '32px';
            spinner.style.animation = 'spin 1s linear infinite';
            spinner.id = 'form-spinner';
            form.appendChild(spinner);
        });
    });

    // Confirm logout
    const logoutLinks = document.querySelectorAll('a[href="logout.php"]');
    logoutLinks.forEach(link => {
        link.addEventListener('click', function (e) {
            if (!confirm('Are you sure you want to logout?')) {
                e.preventDefault();
            }
        });
    });

    // Autofocus on first input of each form for better UX
    forms.forEach(form => {
        const firstInput = form.querySelector('input:not([type="hidden"]):not([disabled])');
        if (firstInput) firstInput.focus();
    });
});

// Spinner animation
const style = document.createElement('style');
style.innerHTML = `
@keyframes spin {
    0% { transform: rotate(0deg);}
    100% { transform: rotate(360deg);}
}
.spinner {
    display: block;
}
`;
document.head.appendChild(style);