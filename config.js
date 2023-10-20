// config.js
require('dotenv').config();

module.exports = {
    PROJECT_ID: process.env.PROJECT_ID,
    SUBSCRIPTION_NAME: process.env.SUBSCRIPTION_NAME,
    TOPIC_NAME: process.env.TOPIC_NAME,
    TOKEN_PATH: process.env.TOKEN_PATH,
    CREDENTIALS_PATH: process.env.CREDENTIALS_PATH,
    SCOPES: process.env.SCOPES,
    SERVICE_CREDENTIALS_PATH: process.env.SERVICE_CREDENTIALS_PATH,
    HTTP_PORT: process.env.HTTP_PORT,
    HTTPS_PORT: process.env.HTTPS_PORT,
    DISCORD_WEBHOOK_URL: process.env.DISCORD_WEBHOOK_URL,
    HTTPS_KEY_PATH: process.env.HTTPS_KEY_PATH,
    HTTPS_CERT_PATH: process.env.HTTPS_CERT_PATH,
};
