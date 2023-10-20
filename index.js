const fs = require('fs');
const readline = require('readline');
const { google } = require('googleapis');
const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const https = require('https');
const http = require('http');
const { PubSub } = require('@google-cloud/pubsub');
const config = require('./config');

const SCOPES = [config.SCOPES];
let gmail;

fs.readFile(config.CREDENTIALS_PATH, (err, content) => {
    if (err) return console.log('Error loading client secret file:', err);
    authorize(JSON.parse(content.toString()), watchInbox);
});

const pubsub = new PubSub({
    projectId: config.PROJECT_ID,
    credentials: require(config.SERVICE_CREDENTIALS_PATH),
});

function authorize(credentials, callback) {
    const { client_secret, client_id, redirect_uris } = credentials.installed;
    const oAuth2Client = new google.auth.OAuth2(client_id, client_secret, redirect_uris[0]);

    fs.readFile(config.TOKEN_PATH, (err, token) => {
        if (err) return getNewToken(oAuth2Client, callback);
        oAuth2Client.setCredentials(JSON.parse(token.toString()));
        callback(oAuth2Client);
    });
}

function getNewToken(oAuth2Client, callback) {
    const authUrl = oAuth2Client.generateAuthUrl({
        access_type: 'offline',
        scope: SCOPES,
    });
    console.log('Authorize this app by visiting this url:', authUrl);
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
    });
    rl.question('Enter the code from that page here: ', (code) => {
        rl.close();
        oAuth2Client.getToken(code, (err, token) => {
            if (err) return console.error('Error retrieving access token', err);
            oAuth2Client.setCredentials(token);
            fs.writeFile(config.TOKEN_PATH, JSON.stringify(token), (err) => {
                if (err) return console.error(err);
                console.log('Token stored to', config.TOKEN_PATH);
            });
            callback(oAuth2Client);
        });
    });
}

let lastHistoryId;

async function watchInbox(auth) {
    gmail = google.gmail({ version: 'v1', auth });
    const topicName = config.TOPIC_NAME;

    try {
        const res = await gmail.users.watch({
            userId: 'me',
            requestBody: {
                labelIds: ['INBOX'],
                topicName,
            },
        });
        console.log('Watch setup successfully:', res.data);
        lastHistoryId = res.data.historyId;
    } catch (error) {
        console.error('Error setting up watch:', error);
    }
}

const app = express();
app.use(bodyParser.json());

app.get('/health', async (req, res) => {
    try {
        const watchStatus = await checkWatchStatus();
        console.log(watchStatus);
        if (watchStatus.active == 'ACTIVE') {
            res.json({ status: 'ok', watchStatus });
        } else {
            console.error('Watch is inactive:', watchStatus);
            res.status(500).json({ status: 'error', watchStatus });
            reRegisterWatch();
        }
    } catch (error) {
        console.error('Error checking watch status:', error);
        res.status(500).json({ status: 'error', error: error.message });
    }
});


let lastMessageId = null;
let processedMessageIds = new Set();

app.post('/notifications', async (req, res) => {
    const messageData = req.body.message.data;
    const decodedData = Buffer.from(messageData, 'base64').toString();
    const { historyId } = JSON.parse(decodedData);

    try {
        const history = await gmail.users.history.list({
            userId: 'me',
            startHistoryId: lastHistoryId,
        });

        lastHistoryId = historyId;

        if (!history.data.history || !Array.isArray(history.data.history)) {
            console.warn('No history records found');
            res.sendStatus(200);
            return;
        }

        for (const record of history.data.history) {
            if (!Array.isArray(record.messages)) {
                throw new Error('Unexpected data structure: record.messages is not an array');
            }

            for (const message of record.messages) {
                if (processedMessageIds.has(message.id) || lastMessageId === message.id) {
                    continue;
                }

                const msg = await gmail.users.messages.get({
                    userId: 'me',
                    id: message.id,
                });

                console.log('Fetched email:', JSON.stringify(msg.data.id, null, 2));

                const emailBody = msg.data.snippet;
                const headers = msg.data.payload.headers;
                const emailSubject = headers.find(header => header.name === 'Subject').value;
                const fromHeader = headers.find(header => header.name === 'From').value;
                const toHeader = headers.find(header => header.name === 'To').value;

                if (emailBody.toLowerCase().includes('steam') && emailBody.toLowerCase().includes('code')) {
                    const usernameMatch = emailBody.match(/Steam (.*?),/);
                    const codeMatch = emailBody.match(/Request made from .*? (\w{5}) /);
                    if (usernameMatch && usernameMatch[1] && codeMatch && codeMatch[1]) {
                        const subject = 'Steam: ' + usernameMatch[1];
                        const body = 'Code: ' + codeMatch[1]; 

                        await postToDiscord(subject, body);
                        console.log('Posted to Discord');

                    } else {
                        console.warn('Could not extract username or code from email body.');
                    }
                }
                else if (emailBody.toLowerCase().includes('epic') && emailBody.toLowerCase().includes('code')) {
                    const codeMatch = emailBody.match(/code (\d+)/);
                    if (codeMatch && codeMatch[1]) {
                        const subject = `Epic Games: ${toHeader}`;
                        const body = `Code: ${codeMatch[1]}`;

                        await postToDiscord(subject, body);
                        console.log('Posted to Discord');

                    } else {
                        console.warn('Could not extract code from Epic Games email body.');
                    }
                }
                else if (emailBody.toLowerCase().includes('battle.net') && emailBody.toLowerCase().includes('code')) {
                    const accountNameMatch = emailBody.match(/If (.*?) isn&#39;t your account name,/);
                    const codeMatch = emailBody.match(/code: (\w+)/i);
                    if (accountNameMatch && accountNameMatch[1] && codeMatch && codeMatch[1]) {
                        const subject = `Battle.net: ${accountNameMatch[1]}`;
                        const body = `Code: ${codeMatch[1]}`;

                        await postToDiscord(subject, body);
                        console.log('Posted to Discord');

                    } else {
                        console.warn('Could not extract account name or code from Battle.net email body.');
                    }
                }
                else if (fromHeader.toLowerCase().includes('rockstar') && emailBody.toLowerCase().includes('code')) {
                    const codeMatch = emailBody.match(/\b(\d{6})\b/);
                    if (codeMatch && codeMatch[1]) {
                        const subject = `Rockstar: ${toHeader}`;
                        const body = `Code: ${codeMatch[1]}`;

                        await postToDiscord(subject, body);
                        console.log('Posted to Discord');

                    } else {
                        console.warn('Could not extract code from Rockstar email body.');
                    }
                }

                lastMessageId = msg.data.id;
                processedMessageIds.add(message.id);

                try {
                    await gmail.users.messages.modify({
                        userId: 'me',
                        id: message.id,
                        requestBody: {
                            removeLabelIds: ['UNREAD'],
                        },
                    });
                    console.log('Message marked as read to prevent further notifications from the same message:', message.id);
                } catch (error) {
                    console.error('Error marking message as read:', error);
                }
            }

        }

        res.sendStatus(200);
    } catch (error) {
        console.error('Error handling notification:', error);
        res.sendStatus(500);
    }
});

const sslOptions = {
    key: fs.readFileSync(config.HTTPS_KEY_PATH),
    cert: fs.readFileSync(config.HTTPS_CERT_PATH)
};

async function postToDiscord(subject, body) {
    const webhookUrl = config.DISCORD_WEBHOOK_URL;
    try {
        await axios.post(webhookUrl, {
            content: `${subject}\n${body}`,
        });
    } catch (error) {
        console.error('Error sending message to Discord:', error);
    }
}

https.createServer(sslOptions, app).listen(config.HTTPS_PORT, () => {
    console.log('Server is listening on port ', config.HTTPS_PORT);
});

http.createServer(app).listen(config.HTTP_PORT, () => {
    console.log('HTTP server is listening on port ', config.HTTP_PORT);
});

function reRegisterWatch() {
    fs.readFile(config.CREDENTIALS_PATH, (err, content) => {
        if (err) return console.log('Error loading client secret file:', err);
        authorize(JSON.parse(content.toString()), watchInbox);
    });
}

setInterval(reRegisterWatch, 24 * 60 * 60 * 1000);

async function checkWatchStatus() {
    try {
        const subscription = pubsub.subscription(config.SUBSCRIPTION_NAME);
        const [metadata] = await subscription.getMetadata();
        return { active: metadata.state };
    } catch (error) {
        console.error('Error checking subscription status:', error);
        return { active: false };
    }
}

setInterval(async () => {
    try {
        const response = await axios.get('http://localhost:' + config.HTTP_PORT + '/health');
        if (response.data.status !== 'ok') {
            console.error('Health check failed:', response.data);
        }
    } catch (error) {
        console.error('Error performing health check:', error);
    }
}, 10 * 60 * 1000);
