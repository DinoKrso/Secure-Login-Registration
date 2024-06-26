document.getElementById('login-form').addEventListener('submit', async function(event) {
    event.preventDefault();

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    const response = await fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password })
    });

    const data = await response.json();

    if (response.ok) {
        // Redirect to dashboard or perform other actions upon successful login
        window.location.href = '/dashboard.html';
    } else {
        document.getElementById('error-message').textContent = data.error || 'Failed to login.';
    }
});
