# gmail-discord-post

1. login to google cloud
2. create new project, save the project id for later

discord-webhook-ffbih

3. Enable Cloub Pub/Sub API for the project that you created
4. Create a new topic selecting the "Add a default subscription" option and save the topic name for later

projects/discord-webhook-ffbih/topics/discord

5. Go to the created subscription and save the subscription name

projects/discord-webhook-ffbih/subscriptions/discord-sub

6. Enable the Gmail API for the project that you created
7. GmailAPI - Oauth consent screen, external app with test user, appropriate scopes such as GmailAPI modify, add yourself as the test user since the app will only be availble to the testing users since it wont be published
8. GmailAPI - Credentials, Create new OAuth credentials for a desktop application and save them to a known location, Create new Service credentials with Cloud Pub/Sub Service agent and Owner roles
9. IAM & Admin - Service Accounts - Keys, Create new key for service account and save it to a known location
