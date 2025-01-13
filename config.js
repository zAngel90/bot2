require('dotenv').config();

const config = {
  server: {
    port: process.env.PORT || 3003,
    host: process.env.HOST || 'localhost'
  },
  cors: {
    origin: '*',
    credentials: true
  },
  api: {
    baseUrl: process.env.API_BASE_URL || 'https://account-public-service-prod.ol.epicgames.com'
  },
  client: {
    id: '3f69e56c7649492c8cc29f1af08a8a12',
    secret: 'b51ee9cb12234f50a69efa67ef53812e',
    platform: 'Android',
    userAgent: 'Fortnite/++Fortnite+Release-24.01-CL-25892170 Android/12'
  }
};

module.exports = config;
