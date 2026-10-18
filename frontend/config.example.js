// Copy this file to config.js and fill it with the outputs of `terraform output`
window.SIEM_CONFIG = {
    apiUrl: "https://xxxxxxxxxx.execute-api.us-east-2.amazonaws.com",
    clientId: "xxxxxxxxxxxxxxxxxxxxxxxxxx",
    loginUrl: "https://siem-lite-dev-123456789012.auth.us-east-2.amazoncognito.com",
    // How often the dashboard asks the API whether a new incident arrived, in seconds
    pollSeconds: 10,
    // Minutes without activity before the session ends (a warning shows 60 seconds before). 0 turns it off
    idleMinutes: 30
};
