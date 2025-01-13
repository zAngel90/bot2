require('dotenv').config();
const express = require('express');
const cors = require('cors');
const https = require('https');
const dns = require('dns').promises;
const fs = require('fs');
const fsPromises = require('fs').promises;
const tls = require('tls');
const qs = require('qs');
const crypto = require('crypto');
const axios = require('axios'); // Importar axios
const HttpsProxyAgent = require('https-proxy-agent');
const jwt = require('jsonwebtoken'); // Importar jwt
const path = require('path');

console.log('Variables de entorno cargadas:', {
  DLOCAL_API_KEY: process.env.DLOCAL_API_KEY ? 'Configurada' : 'No configurada',
  DLOCAL_SECRET_KEY: process.env.DLOCAL_SECRET_KEY ? 'Configurada' : 'No configurada'
});

const app = express();

// Middleware global
app.use(express.json());
app.use(cors({
  origin: ['https://lobomatshop.com', 'http://localhost:5173', 'localhost:5173'],
  methods: ['GET', 'POST', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
  exposedHeaders: ['Content-Length', 'X-Foo', 'X-Bar'],
}));

// Middleware para manejar preflight requests
app.options('*', cors());

// Middleware para logging de requests
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} ${req.method} ${req.path}`);
  next();
});

// Configurar todas las rutas bajo /bot2
app.use('/bot2', (req, res, next) => {
  console.log('Bot 2 request:', req.path);
  next();
});

// Estado del bot
let botStatus = {
    deviceId: null,
    accessToken: null,
    accountId: null,
    expiresAt: null,
    isAuthenticated: false
};

// Variables globales
const pendingRequests = new Map();

// Función para generar ID único para solicitudes pendientes
function generateRequestId() {
    return Date.now().toString(36) + Math.random().toString(36).substr(2);
}

// Función para obtener token de acceso
async function getAccessToken() {
    try {
        // Si ya tenemos un token válido, lo devolvemos
        if (botStatus.accessToken && botStatus.expiresAt > Date.now()) {
            return botStatus.accessToken;
        }

        console.log('🔑 Obteniendo nuevo token usando device auth...');
        
        // Leer el device auth
        const deviceAuthData = JSON.parse(await fsPromises.readFile('deviceAuth.json', 'utf8'));
        console.log('📄 Device Auth cargado:', {
            deviceId: deviceAuthData.deviceId,
            accountId: deviceAuthData.accountId,
            hasSecret: !!deviceAuthData.secret
        });

        const response = await axios.post(
            'https://account-public-service-prod.ol.epicgames.com/account/api/oauth/token',
            qs.stringify({
                grant_type: 'device_auth',
                device_id: deviceAuthData.deviceId,
                account_id: deviceAuthData.accountId,
                secret: deviceAuthData.secret
            }),
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Authorization': 'Basic M2Y2OWU1NmM3NjQ5NDkyYzhjYzI5ZjFhZjA4YThhMTI6YjUxZWU5Y2IxMjIzNGY1MGE2OWVmYTY3ZWY1MzgxMmU=',
                    'User-Agent': 'Fortnite/++Fortnite+Release-24.01-CL-27526713 Android/11'
                }
            }
        );

        if (response.data && response.data.access_token) {
            console.log('✅ Token obtenido exitosamente');
            botStatus.accessToken = response.data.access_token;
            botStatus.expiresAt = Date.now() + (response.data.expires_in * 1000);
            botStatus.accountId = deviceAuthData.accountId;
            return response.data.access_token;
        } else {
            console.error('❌ Respuesta inválida al obtener token:', response.data);
            throw new Error('Respuesta inválida al obtener token');
        }
    } catch (error) {
        console.error('❌ Error obteniendo token:', error.response?.data || error.message);
        throw new Error(`No se pudo obtener el token de acceso. Status: ${error.response?.status}. Response: ${JSON.stringify(error.response?.data)}`);
    }
}

// Función para obtener información del usuario
async function getUserInfo(accessToken) {
    try {
        const options = {
            hostname: 'account-public-service-prod.ol.epicgames.com',
            port: 443,
            path: '/account/api/oauth/verify',
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${accessToken}`
            },
            ...defaultTlsOptions
        };

        return new Promise((resolve, reject) => {
            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', (chunk) => {
                    data += chunk;
                });

                res.on('end', () => {
                    console.log('Respuesta completa del usuario:', data);

                    if (!res.statusCode || res.statusCode >= 400) {
                        reject(new Error(`No se pudo obtener la información del usuario. Status: ${res.statusCode}. Response: ${data}`));
                        return;
                    }

                    try {
                        const userData = JSON.parse(data);
                        resolve(userData);
                    } catch (e) {
                        reject(new Error(`Error al parsear la respuesta del usuario: ${data}`));
                    }
                });
            });

            req.on('error', (error) => {
                console.error('Error al obtener información del usuario:', error);
                reject(error);
            });

            req.on('timeout', () => {
                req.destroy();
                reject(new Error('Timeout al obtener información del usuario'));
            });

            req.end();
        });
    } catch (error) {
        console.error('Error al obtener información del usuario:', error);
        throw error;
    }
}

// Función para validar el username antes de la solicitud de amistad
async function validateFriendUsername(username) {
    try {
        // Asegurarse de que el bot esté autenticado
        await ensureBotAuthenticated();
        
        // Obtener el ID de la cuenta del usuario
        console.log('🔍 Validando usuario:', username);
        const userData = await getAccountIdByUsername(username);
        if (!userData || !userData.id) {
            throw new Error('No se pudo encontrar el usuario');
        }
        return userData;
    } catch (error) {
        console.error('❌ Error al validar usuario:', error);
        throw error;
    }
}

// Endpoint para validar username
app.post('/bot2/api/validate-friend', async (req, res) => {
    try {
        const { username } = req.body;
        
        if (!username) {
            throw new Error('Se requiere un nombre de usuario');
        }

        const result = await validateFriendUsername(username);
        res.json(result);

    } catch (error) {
        console.error('❌ Error al validar usuario:', error);
        res.status(500).json({ error: error.message });
    }
});

// Endpoint para enviar solicitud de amistad
app.post('/bot2/api/friend-request', async (req, res) => {
    try {
        const { username } = req.body;
        
        if (!username) {
            return res.status(400).json({
                success: false,
                error: 'Se requiere un nombre de usuario'
            });
        }

        // Asegurarnos que el bot esté autenticado
        if (!botStatus.isAuthenticated || !botStatus.accessToken) {
            return res.status(401).json({
                success: false,
                error: 'Bot no autenticado'
            });
        }

        // Usar el token del bot directamente
        try {
            const userData = await validateFriendUsername(username);
            const result = await sendFriendRequestToEpic(username, botStatus.accessToken);
            return res.json(result);
        } catch (error) {
            console.error('❌ Error al enviar solicitud:', error);
            return res.status(500).json({
                success: false,
                error: error.message
            });
        }
    } catch (error) {
        console.error('❌ Error al procesar solicitud:', error);
        res.status(500).json({ 
            success: false,
            error: 'Error interno del servidor'
        });
    }
});

// Función para enviar solicitud de amistad
async function sendFriendRequestToEpic(username, accessToken) {
    try {
        console.log('📨 Enviando solicitud de amistad a:', username);
        
        // Validar el usuario y obtener su ID
        const userData = await validateFriendUsername(username);
        // Limpiar el ID de cualquier prefijo
        const cleanId = userData.id.replace(/^(epic|psn|xbl|nintendo)_/, '');
        
        // Obtener el ID de la cuenta que envía la solicitud
        const accountId = botStatus.accountId;
        
        console.log('🔄 Enviando solicitud desde:', accountId, 'para:', cleanId);
        
        const response = await axios({
            method: 'POST',
            url: `https://friends-public-service-prod.ol.epicgames.com/friends/api/v1/${accountId}/friends/${cleanId}`,
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': 'application/json',
                'User-Agent': 'Fortnite/++Fortnite+Release-24.01-CL-27526713 Android/11'
            },
            validateStatus: function (status) {
                return status === 204 || status >= 200 && status < 300 || status === 409;
            }
        });

        // Si la solicitud ya fue enviada, lo consideramos como éxito
        if (response.status === 409 && response.data?.errorCode === 'errors.com.epicgames.friends.friend_request_already_sent') {
            return { 
                success: true, 
                message: `Ya enviaste una solicitud de amistad a ${username}. Espera a que la acepte.`,
                alreadySent: true
            };
        }

        if (response.status === 204 || response.status === 200) {
            return { 
                success: true, 
                message: `Solicitud de amistad enviada correctamente a ${username}` 
            };
        }

        throw new Error(response.data?.errorMessage || 'Error al enviar la solicitud');
    } catch (error) {
        console.error('❌ Error al enviar solicitud:', error.response?.data || error.message);
        throw new Error(error.response?.data?.errorMessage || 'Error al enviar la solicitud de amistad');
    }
}

// Endpoint para recibir token de amigos
app.post('/bot2/api/friend-token', async (req, res) => {
    try {
        const { friendToken } = req.body;
        
        if (!friendToken) {
            return res.status(400).json({
                success: false,
                message: 'Token no proporcionado'
            });
        }

        try {
            // Si es un token hexadecimal, convertirlo a OAuth
            if (/^[0-9a-fA-F]{32}$/.test(friendToken)) {
                const oauthToken = await exchangeHexTokenForOAuth(friendToken);
                botStatus.friendToken = oauthToken.access_token;
                console.log('✅ Token OAuth guardado:', oauthToken.access_token.substring(0, 10) + '...');
            } else {
                botStatus.friendToken = friendToken;
            }

            return res.json({
                success: true,
                message: 'Token guardado correctamente'
            });
        } catch (error) {
            console.error('❌ Error al procesar el token:', error);
            return res.status(400).json({
                success: false,
                message: 'Error al procesar el token. Asegúrate de que sea válido.'
            });
        }
    } catch (error) {
        console.error('❌ Error en /api/friend-token:', error);
        return res.status(500).json({
            success: false,
            message: 'Error interno del servidor'
        });
    }
});

// Endpoint para obtener el estado del bot
app.get('/bot2/api/bot-status', async (req, res) => {
    try {
        const status = {
            isReady: true, // El bot está listo para recibir peticiones
            isAuthenticated: botStatus.accessToken !== null,
            displayName: botStatus.displayName || null,
            lastError: null,
            hasFriendToken: botStatus.deviceId !== null
        };
        
        res.json(status);
    } catch (error) {
        console.error('Error al obtener estado del bot:', error);
        res.status(500).json({ 
            isReady: false,
            isAuthenticated: false,
            displayName: null,
            lastError: error.message,
            hasFriendToken: false
        });
    }
});

// Función para verificar si el token del bot ha expirado
function isBotTokenExpired() {
    if (!botStatus.expiresAt) return true;
    return Date.now() >= botStatus.expiresAt;
}

// Función para refrescar el token del bot si es necesario
async function ensureBotAuthenticated() {
    if (!botStatus.isAuthenticated || isBotTokenExpired()) {
        console.log('🔄 Token del bot expirado o no presente, reautenticando...');
        botStatus.lastError = 'Token expirado o no presente';
        botStatus.isAuthenticated = false;
        throw new Error('Bot necesita reautenticación');
    }
    return botStatus.accessToken;
}

// Función para actualizar el estado del bot
function updateBotStatus(newStatus) {
    console.log('🔄 Actualizando estado del bot:', {
        ...newStatus,
        accessToken: '***token***'
    });
    
    botStatus = {
        ...botStatus,
        ...newStatus
    };
    
    console.log('✅ Estado actualizado:', {
        deviceId: botStatus.deviceId,
        accountId: botStatus.accountId,
        expiresAt: botStatus.expiresAt,
        isAuthenticated: botStatus.isAuthenticated
    });
}

// Función para resetear el estado del bot
function resetBotStatus() {
    console.log('🔄 Estado del bot reseteado');
    updateBotStatus({
        deviceId: null,
        accessToken: null,
        accountId: null,
        expiresAt: null,
        isAuthenticated: false
    });
}

// Función para verificar y formatear el token
function formatAuthToken(token) {
    if (!token) return null;
    
    // Nunca modificar el token, devolverlo tal cual
    return token;
}

// Función para obtener accountId por displayName
async function getAccountIdByUsername(username) {
    try {
        console.log("🔍 Buscando ID para usuario:", username);

        if (!botStatus || !botStatus.accessToken) {
            throw new Error('Bot no autenticado');
        }

        const response = await axios.get(
            `https://account-public-service-prod.ol.epicgames.com/account/api/public/account/displayName/${username}`,
            {
                headers: {
                    'Authorization': `Bearer ${botStatus.accessToken}`,
                    'Content-Type': 'application/json'
                }
            }
        );

        console.log("✅ Usuario encontrado:", response.data);
        return response.data;
    } catch (error) {
        console.error("❌ Error en getAccountIdByUsername:", error.message);
        if (error.response?.status === 404) {
            return null;
        }
        throw error;
    }
}

// Ruta para verificar amistad
app.get('/bot2/api/check-friendship/:username', async (req, res) => {
    try {
        const { username } = req.params;
        console.log('🔍 Verificando amistad con:', username);

        // Usar la variable global botStatus directamente
        if (!botStatus || !botStatus.accessToken) {
            throw new Error('Bot no autenticado');
        }

        // Primero obtener el accountId del usuario
        const userInfo = await getAccountIdByUsername(username);
        if (!userInfo || !userInfo.id) {
            return res.status(404).json({
                success: false,
                error: 'Usuario no encontrado'
            });
        }

        const result = await checkFriendship(botStatus, userInfo.id);
        res.json(result);
    } catch (error) {
        console.error('Error verificando amistad:', error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Función para verificar si un usuario es amigo
async function checkFriendship(botStatus, accountId) {
    try {
        if (!accountId) {
            throw new Error('Se requiere el ID de la cuenta');
        }

        console.log(`🤝 Verificando amistad con: ${accountId}`);
        
        const response = await axios.get(
            `https://friends-public-service-prod.ol.epicgames.com/friends/api/v1/${botStatus.accountId}/friends/${accountId}`,
            {
                headers: {
                    'Authorization': `Bearer ${botStatus.accessToken}`
                }
            }
        );

        // Si llegamos aquí, significa que son amigos (si no, habría lanzado 404)
        const friendshipData = response.data;
        console.log("✅ Estado de amistad:", friendshipData);

        // Calcular el tiempo de amistad
        const created = new Date(friendshipData.created);
        const now = new Date();
        const hoursDiff = Math.floor((now - created) / (1000 * 60 * 60));

        console.log("⏰ Tiempo de amistad:", {
            created: created.toISOString(),
            now: now.toISOString(),
            hours: hoursDiff,
            days: Math.floor(hoursDiff / 24)
        });

        return {
            success: true,
            accountId: accountId,
            isFriend: true,
            hasMinTime: hoursDiff >= 48,
            timeRemaining: hoursDiff < 48 ? 48 - hoursDiff : 0,
            created: created.toISOString(),
            hoursAsFriends: hoursDiff
        };
    } catch (error) {
        if (error.response?.status === 404) {
            return {
                success: false,
                isFriend: false,
                hasMinTime: false,
                timeRemaining: 48,
                error: 'Usuario no encontrado en la lista de amigos'
            };
        }
        console.error("Error verificando amistad:", error);
        throw error;
    }
}

// Endpoint para autenticación del bot
app.post('/bot2/api/auth', async (req, res) => {
    try {
        // Primero intentar usar Device Auth existente
        try {
            console.log('🔄 Intentando usar Device Auth existente...');
            const deviceAuth = await setupDeviceAuth();
            
            if (deviceAuth) {
                console.log('🔑 Device Auth encontrado, intentando autenticar...');
                // Usar Device Auth para autenticación
                const response = await axios({
                    method: 'POST',
                    url: 'https://account-public-service-prod.ol.epicgames.com/account/api/oauth/token',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                        'Authorization': 'Basic M2Y2OWU1NmM3NjQ5NDkyYzhjYzI5ZjFhZjA4YThhMTI6YjUxZWU5Y2IxMjIzNGY1MGE2OWVmYTY3ZWY1MzgxMmU=',
                        'User-Agent': 'Fortnite/++Fortnite+Release-24.01-CL-27526713 Android/11'
                    },
                    ...defaultTlsOptions
                });

                if (response.data && response.data.access_token) {
                    updateBotStatus({
                        deviceId: deviceAuth.deviceId,
                        accessToken: response.data.access_token,
                        accountId: deviceAuth.accountId,
                        expiresAt: Date.now() + response.data.expires_in * 1000,
                        isAuthenticated: true
                    });
                    console.log('✅ Bot autenticado exitosamente con Device Auth');
                }
            }
        } catch (deviceAuthError) {
            console.log('❌ Error usando Device Auth:', deviceAuthError.message);
        }

        // Si Device Auth falla o no existe, usar autenticación normal
        const { code } = req.body;
        if (!code) {
            throw new Error('Código de autorización requerido');
        }

        // Primero autenticar normalmente
        const tokenData = await authenticateBot(code);
        console.log('✅ Token obtenido correctamente');
        
        // Actualizar tokens
        updateBotStatus({
            accessToken: tokenData.access_token,
            refreshToken: tokenData.refresh_token,
            expiresAt: Date.now() + (tokenData.expires_in * 1000)
        });

        // Obtener información del usuario
        const userInfo = await getUserInfo(tokenData.access_token);
        
        // Actualizar información del bot
        updateBotStatus({
            accountId: userInfo.account_id,
            isAuthenticated: true,
            lastError: null
        });

        // AHORA intentar crear Device Auth
        await setupDeviceAuth();

        res.json({
            success: true,
            displayName: userInfo.display_name
        });
    } catch (error) {
        console.error('❌ Error al autenticar bot:', error.message);
        updateBotStatus({
            isAuthenticated: false,
            lastError: error.message
        });
        res.status(500).json({ error: error.message });
    }
});

// Endpoint para reiniciar el bot
app.post('/bot2/api/reset', async (req, res) => {
    try {
        resetBotStatus();
        
        console.log('🔄 Bot reiniciado correctamente');
        res.json({ success: true });
    } catch (error) {
        console.error('❌ Error al reiniciar bot:', error);
        res.status(500).json({ error: error.message });
    }
});

// Función para intercambiar token hexadecimal por token OAuth
async function exchangeHexTokenForOAuth(hexToken) {
    try {
        console.log('🔄 Intercambiando token hexadecimal por token OAuth...');
        
        const options = {
            hostname: 'account-public-service-prod.ol.epicgames.com',
            port: 443,
            path: '/account/api/oauth/token',
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': 'Basic M2Y2OWU1NmM3NjQ5NDkyYzhjYzI5ZjFhZjA4YThhMTI6YjUxZWU5Y2IxMjIzNGY1MGE2OWVmYTY3ZWY1MzgxMmU=',
                'User-Agent': 'Fortnite/++Fortnite+Release-24.01-CL-27526713 Android/11'
            },
            ...defaultTlsOptions
        };

        const body = qs.stringify({
            grant_type: 'authorization_code',
            code: hexToken,
            token_type: 'eg1'
        });

        return new Promise((resolve, reject) => {
            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', (chunk) => {
                    data += chunk;
                });

                res.on('end', () => {
                    console.log('Respuesta completa del token:', data);

                    if (!res.statusCode || res.statusCode >= 400) {
                        reject(new Error(`No se pudo obtener el token OAuth. Status: ${res.statusCode}. Response: ${data}`));
                        return;
                    }

                    try {
                        const tokenData = JSON.parse(data);
                        resolve(tokenData);
                    } catch (e) {
                        reject(new Error(`Error al parsear la respuesta del token: ${data}`));
                    }
                });
            });

            req.on('error', (error) => {
                console.error('Error al obtener token:', error);
                reject(error);
            });

            req.on('timeout', () => {
                req.destroy();
                reject(new Error('Timeout al obtener token'));
            });

            req.write(body);
            req.end();
        });
    } catch (error) {
        console.error('Error al intercambiar token:', error);
        throw new Error('No se pudo obtener el token OAuth. Por favor, obtén un nuevo token.');
    }
}

// Endpoint para obtener el catálogo sin procesar
app.get('/bot2/api/raw-catalog', async (req, res) => {
    try {
        const catalog = await getCurrentCatalog();
        res.json(catalog);
    } catch (error) {
        console.error('Error al obtener el catálogo:', error);
        res.status(500).json({ 
            error: 'Error al obtener el catálogo',
            message: error.message 
        });
    }
});

// Función para obtener el catálogo actual
async function getCurrentCatalog() {
    try {
        console.log('📦 Obteniendo catálogo de Epic Games...');
        
        const response = await axios.get(
            'https://fortnite-public-service-prod11.ol.epicgames.com/fortnite/api/storefront/v2/catalog',
            {
                headers: {
                    'Authorization': 'Bearer ' + await getAccessToken(),
                    'Content-Type': 'application/json',
                    'User-Agent': 'Fortnite/++Fortnite+Release-24.01-CL-27526713 Android/11'
                }
            }
        );

        return response.data;
    } catch (error) {
        console.error('Error obteniendo catálogo:', error.message);
        throw error;
    }
}

// Función para extraer precio del devName
function extractPriceFromDevName(devName) {
    const match = devName.match(/for (\d+) (\w+)/);
    if (match) {
        return {
            basePrice: parseInt(match[1]),
            currencyType: match[2]
        };
    }
    return null;
}

// Función para obtener el balance de V-Bucks
async function getBalance() {
    try {
        await ensureBotAuthenticated();
        
        const options = {
            hostname: 'fortnite-public-service-prod11.ol.epicgames.com',
            path: `/fortnite/api/game/v2/profile/${botStatus.accountId}/client/QueryProfile?profileId=common_core&rvn=-1`,
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${botStatus.accessToken}`,
                'Content-Type': 'application/json'
            },
            ...defaultTlsOptions
        };

        const response = await new Promise((resolve, reject) => {
            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', (chunk) => {
                    data += chunk;
                });

                res.on('end', () => {
                    try {
                        resolve(JSON.parse(data));
                    } catch (e) {
                        reject(new Error('Error parsing response: ' + e.message));
                    }
                });
            });
            req.on('error', reject);
            req.write('{}');
            req.end();
        });

        if (!response || !response.profileChanges || !response.profileChanges[0] || !response.profileChanges[0].profile) {
            throw new Error('Formato de respuesta inválido');
        }

        const profile = response.profileChanges[0].profile;
        let mtxBalance = 0;

        // Buscar el balance de V-Bucks en los items del perfil
        if (profile.items) {
            for (const [itemId, item] of Object.entries(profile.items)) {
                if (item.templateId === 'Currency:MtxPurchased') {
                    mtxBalance = item.quantity || 0;
                    break;
                }
            }
        }

        console.log('Balance de V-Bucks obtenido:', mtxBalance);
        return mtxBalance;
    } catch (error) {
        console.error('Error obteniendo balance:', error);
        throw new Error('No se pudo obtener el balance de V-Bucks: ' + error.message);
    }
}

// Función para obtener y validar el balance de V-Bucks
async function getVBucksBalance() {
    try {
        if (!botStatus.isAuthenticated) {
            throw new Error('Bot no autenticado');
        }

        const balance = await getBalance();
        if (typeof balance !== 'number' || balance < 0) {
            throw new Error('Balance inválido recibido');
        }

        console.log('Balance de V-Bucks validado:', balance);
        return balance;
    } catch (error) {
        console.error('Error en getVBucksBalance:', error);
        throw error;
    }
}

// Endpoint para enviar regalos
app.post('/bot2/api/send-gift', async (req, res) => {
    try {
        const { username, offerId, price, isBundle = false } = req.body;

        if (!username || !offerId) {
            return res.status(400).json({
                success: false,
                message: 'Se requiere username y offerId'
            });
        }

        if (!price || typeof price !== 'number' || price <= 0) {
            return res.status(400).json({
                success: false,
                message: 'Se requiere un precio válido'
            });
        }

        console.log('📦 Preparando regalo:', {
            username,
            offerId,
            price,
            isBundle
        });

        // Obtener el accountId del usuario
        const userInfo = await getAccountIdByUsername(username);
        if (!userInfo || !userInfo.id) {
            return res.status(404).json({
                success: false,
                message: 'Usuario no encontrado'
            });
        }

        // Verificar que el item existe en el catálogo
        const catalog = await getCurrentCatalog();
        const catalogItem = catalog.storefronts.find(sf => 
            sf.catalogEntries?.some(entry => {
                const searchOfferId = !offerId.startsWith('v2:/') ? `v2:/${offerId}` : offerId;
                return entry.offerId === searchOfferId;
            })
        );

        if (!catalogItem) {
            return res.status(404).json({
                success: false,
                message: 'Item no encontrado en el catálogo actual'
            });
        }

        // Enviar el regalo
        const giftResult = await sendGift(userInfo.id, offerId, price, isBundle);
        
        res.json({
            success: true,
            message: 'Regalo enviado exitosamente',
            data: giftResult
        });
    } catch (error) {
        console.error('❌ Error al enviar regalo:', error);
        
        // Si es error de V-Bucks insuficientes
        if (error.message === 'NOT_ENOUGH_VBUCKS' || 
            error.response?.data?.errorCode === 'errors.com.epicgames.modules.gameplayutils.not_enough_mtx') {
            return res.status(400).json({
                success: false,
                message: 'NOT_ENOUGH_VBUCKS',
                errorCode: 'not_enough_vbucks'
            });
        }

        // Para otros errores de Epic Games
        if (error.response?.data?.errorMessage) {
            return res.status(400).json({
                success: false,
                message: error.response.data.errorMessage,
                errorCode: error.response.data.errorCode
            });
        }

        res.status(500).json({
            success: false,
            message: error.message || 'Error al enviar regalo'
        });
    }
});

async function sendGift(accountId, offerId, price, isBundle = false) {
    try {
        console.log('🎁 Intentando enviar regalo:', { accountId, offerId, price, isBundle });

        // Obtener el estado de amistad
        const friendshipStatus = await checkFriendship(botStatus, accountId);
        if (!friendshipStatus.success || !friendshipStatus.isFriend) {
            throw new Error('No eres amigo de este usuario');
        }
        if (!friendshipStatus.hasMinTime) {
            throw new Error(`Debes esperar ${Math.ceil(friendshipStatus.timeRemaining)} horas más para poder enviar regalos a este amigo`);
        }

        // Normalizar el offerId si es necesario
        const normalizedOfferId = !offerId.startsWith('v2:/') ? `v2:/${offerId}` : offerId;

        // Construir el payload para el regalo
        const giftPayload = {
            offerId: normalizedOfferId,
            purchaseQuantity: 1,
            currency: "MtxCurrency",
            currencySubType: "",
            expectedTotalPrice: price,
            gameContext: "Frontend.CatabaScreen",
            receiverAccountIds: [accountId],
            giftWrapTemplateId: "",
            personalMessage: ""
        };

        console.log('📦 Enviando regalo con payload:', giftPayload);

        // Enviar el regalo
        const response = await axios.post(
            'https://fortnite-public-service-prod11.ol.epicgames.com/fortnite/api/game/v2/profile/' + botStatus.accountId + '/client/GiftCatalogEntry?profileId=common_core',
            giftPayload,
            {
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + await getAccessToken()
                }
            }
        );

        console.log('✅ Regalo enviado exitosamente:', response.data);
        return { success: true, data: response.data };
    } catch (error) {
        console.error('Error detallado en sendGift:', {
            message: error.message,
            response: error.response?.data,
            status: error.response?.status,
            headers: error.response?.headers
        });

        // Si es error de V-Bucks insuficientes, lanzar un error específico
        if (error.response?.data?.errorCode === 'errors.com.epicgames.modules.gameplayutils.not_enough_mtx') {
            throw new Error('NOT_ENOUGH_VBUCKS');
        }

        // Si es otro tipo de error de Epic, enviar el mensaje exacto
        if (error.response?.data?.errorMessage) {
            throw new Error(error.response.data.errorMessage);
        }

        throw error;
    }
}

// Función para verificar si un usuario es amigo
async function checkFriendship(botStatus, accountId) {
    try {
        if (!accountId) {
            throw new Error('Se requiere el ID de la cuenta');
        }

        console.log(`🤝 Verificando amistad con: ${accountId}`);
        
        const response = await axios.get(
            `https://friends-public-service-prod.ol.epicgames.com/friends/api/v1/${botStatus.accountId}/friends/${accountId}`,
            {
                headers: {
                    'Authorization': `Bearer ${botStatus.accessToken}`
                }
            }
        );

        // Si llegamos aquí, significa que son amigos (si no, habría lanzado 404)
        const friendshipData = response.data;
        console.log("✅ Estado de amistad:", friendshipData);

        // Calcular el tiempo de amistad
        const created = new Date(friendshipData.created);
        const now = new Date();
        const hoursDiff = Math.floor((now - created) / (1000 * 60 * 60));

        console.log("⏰ Tiempo de amistad:", {
            created: created.toISOString(),
            now: now.toISOString(),
            hours: hoursDiff,
            days: Math.floor(hoursDiff / 24)
        });

        return {
            success: true,
            accountId: accountId,
            isFriend: true,
            hasMinTime: hoursDiff >= 48,
            timeRemaining: hoursDiff < 48 ? 48 - hoursDiff : 0,
            created: created.toISOString(),
            hoursAsFriends: hoursDiff
        };
    } catch (error) {
        if (error.response?.status === 404) {
            return {
                success: false,
                isFriend: false,
                hasMinTime: false,
                timeRemaining: 48,
                error: 'Usuario no encontrado en la lista de amigos'
            };
        }
        console.error("Error verificando amistad:", error);
        throw error;
    }
}

// Ruta para verificar amistad
app.get('/bot2/api/check-friendship/:username', async (req, res) => {
    try {
        const { username } = req.params;
        
        if (!username) {
            throw new Error('Se requiere el nombre de usuario');
        }

        console.log("🔍 Buscando ID para usuario:", username);
        
        // Obtener el ID de la cuenta del usuario
        const accountInfo = await getAccountIdByUsername(username);
        if (!accountInfo) {
            throw new Error('Usuario no encontrado');
        }

        console.log("✅ Usuario encontrado:", accountInfo);

        // Verificar la amistad usando el ID
        const friendshipStatus = await checkFriendship(botStatus, accountInfo.id);
        
        res.json(friendshipStatus);
    } catch (error) {
        console.error("Error verificando amistad:", error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Agregar nueva función para manejar Device Auth
const deviceAuthPath = path.join(__dirname, 'deviceAuth.json');

async function loadDeviceAuth() {
    try {
        console.log('🔄 Intentando cargar Device Auth existente...');
        const deviceAuthData = await fsPromises.readFile(deviceAuthPath, 'utf8');
        const deviceAuth = JSON.parse(deviceAuthData);
        console.log('✅ Device Auth cargado correctamente');
        console.log('🔑 Usando Device Auth para:', deviceAuth.accountId);

        // Realizar autenticación inicial
        const response = await axios.post('https://account-public-service-prod.ol.epicgames.com/account/api/oauth/token',
            {
                grant_type: 'device_auth',
                account_id: deviceAuth.accountId,
                device_id: deviceAuth.deviceId,
                secret: deviceAuth.secret
            },
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Authorization': 'Basic M2Y2OWU1NmM3NjQ5NDkyYzhjYzI5ZjFhZjA4YThhMTI6YjUxZWU5Y2IxMjIzNGY1MGE2OWVmYTY3ZWY1MzgxMmU=',
                    'User-Agent': 'Fortnite/++Fortnite+Release-24.01-CL-27526713 Android/11'
                }
            }
        );

        // Actualizar el estado del bot
        botStatus = {
            accessToken: response.data.access_token,
            accountId: deviceAuth.accountId,
            expiresAt: new Date(Date.now() + response.data.expires_in * 1000).toISOString()
        };

        console.log('✅ Bot autenticado exitosamente');
        return deviceAuth;
    } catch (error) {
        console.error('❌ Error al cargar Device Auth:', error);
        throw error;
    }
}

loadDeviceAuth();

// Función para configurar el Device Auth
async function setupDeviceAuth() {
    try {
        console.log('🔄 Intentando cargar Device Auth existente...');
        const deviceAuthData = await fsPromises.readFile(deviceAuthPath, 'utf8');
        const deviceAuth = JSON.parse(deviceAuthData);
        console.log('✅ Device Auth cargado correctamente');
        console.log('🔑 Usando Device Auth para:', deviceAuth.accountId);

        // Realizar autenticación inicial
        const response = await axios.post('https://account-public-service-prod.ol.epicgames.com/account/api/oauth/token',
            {
                grant_type: 'device_auth',
                account_id: deviceAuth.accountId,
                device_id: deviceAuth.deviceId,
                secret: deviceAuth.secret
            },
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Authorization': 'Basic M2Y2OWU1NmM3NjQ5NDkyYzhjYzI5ZjFhZjA4YThhMTI6YjUxZWU5Y2IxMjIzNGY1MGE2OWVmYTY3ZWY1MzgxMmU=',
                    'User-Agent': 'Fortnite/++Fortnite+Release-24.01-CL-27526713 Android/11'
                }
            }
        );

        // Actualizar el estado del bot
        botStatus = {
            accessToken: response.data.access_token,
            accountId: deviceAuth.accountId,
            expiresAt: new Date(Date.now() + response.data.expires_in * 1000).toISOString()
        };

        console.log('✅ Bot autenticado exitosamente');

        // Configurar reinicio programado
        setInterval(async () => {
            try {
                console.log('🔄 Realizando reinicio programado...');
                const deviceAuthData = await fsPromises.readFile(deviceAuthPath, 'utf8');
                const deviceAuth = JSON.parse(deviceAuthData);
                
                const response = await axios.post('https://account-public-service-prod.ol.epicgames.com/account/api/oauth/token',
                    {
                        grant_type: 'device_auth',
                        account_id: deviceAuth.accountId,
                        device_id: deviceAuth.deviceId,
                        secret: deviceAuth.secret
                    },
                    {
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                            'Authorization': 'Basic M2Y2OWU1NmM3NjQ5NDkyYzhjYzI5ZjFhZjA4YThhMTI6YjUxZWU5Y2IxMjIzNGY1MGE2OWVmYTY3ZWY1MzgxMmU=',
                            'User-Agent': 'Fortnite/++Fortnite+Release-24.01-CL-27526713 Android/11'
                        }
                    }
                );

                botStatus = {
                    accessToken: response.data.access_token,
                    accountId: deviceAuth.accountId,
                    expiresAt: new Date(Date.now() + response.data.expires_in * 1000).toISOString()
                };

                console.log('✅ Token actualizado correctamente');
            } catch (error) {
                console.error('❌ Error al actualizar token:', error);
            }
        }, 3600000); // Cada hora

        return deviceAuth;
    } catch (error) {
        console.error('❌ Error cargando Device Auth:', error);
        throw error;
    }
}

async function getAuth() {
    try {
        // Leer el device auth
        const deviceAuthData = JSON.parse(await fsPromises.readFile(deviceAuthPath, 'utf8'));
        
        // Obtener token usando device auth
        const response = await axios.post('https://account-public-service-prod.ol.epicgames.com/account/api/oauth/token',
            {
                grant_type: 'device_auth',
                account_id: deviceAuthData.accountId,
                device_id: deviceAuthData.deviceId,
                secret: deviceAuthData.secret
            },
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Authorization': 'Basic M2Y2OWU1NmM3NjQ5NDkyYzhjYzI5ZjFhZjA4YThhMTI6YjUxZWU5Y2IxMjIzNGY1MGE2OWVmYTY3ZWY1MzgxMmU=',
                    'User-Agent': 'Fortnite/++Fortnite+Release-24.01-CL-27526713 Android/11'
                }
            }
        );

        return {
            success: true,
            access_token: response.data.access_token,
            account_id: deviceAuthData.accountId,
            expires_at: new Date(Date.now() + response.data.expires_in * 1000).toISOString()
        };
    } catch (error) {
        console.error('Error obteniendo autenticación:', error);
        return {
            success: false,
            error: error.message
        };
    }
}

// Iniciar el servidor y configurar Device Auth
const port = process.env.PORT || 8080;
app.listen(port, () => {
    console.log(`\n🚀 Bot 2 iniciado en puerto ${port}`);
    console.log(`URL base: ${process.env.NODE_ENV === 'production' ? 'https://lobomatshop.com/bot2' : `http://localhost:${port}/bot2`}`);
    setupAutoRestart();
});

// Webhook para notificaciones de dLocal
app.post('/bot2/api/payment-webhook', async (req, res) => {
    try {
        const notification = req.body;
        console.log('Notificación de pago recibida:', notification);

        // Verificar la autenticidad de la notificación
        const signature = req.headers['x-dlocal-signature'];
        if (!verifyDLocalSignature(notification, signature)) {
            throw new Error('Firma inválida');
        }

        // Procesar según el estado del pago
        switch (notification.status) {
            case 'PAID':
                // El pago fue exitoso
                // Aquí deberías implementar la lógica para enviar el regalo
                const { order_id } = notification;
                // Buscar la orden en tu base de datos y procesarla
                break;

            case 'REJECTED':
                // El pago fue rechazado
                // Actualizar el estado de la orden
                break;

            case 'EXPIRED':
                // El pago expiró
                // Limpiar la orden pendiente
                break;
        }

        res.json({ success: true });
    } catch (error) {
        console.error('Error procesando webhook:', error);
        res.status(500).json({ error: error.message });
    }
});

// Función para verificar la firma de dLocal
function verifyDLocalSignature(payload, signature) {
    const secret = process.env.DLOCAL_SECRET_KEY;
    const calculatedSignature = crypto
        .createHmac('sha256', secret)
        .update(JSON.stringify(payload))
        .digest('hex');
    
    return signature === calculatedSignature;
}

// Proxy para dLocal
app.post('/bot2/api/dlocal-proxy', async (req, res) => {
  try {
    const apiKey = process.env.DLOCAL_API_KEY;
    const secretKey = process.env.DLOCAL_SECRET_KEY;
    
    // Verificar que las credenciales existen
    if (!apiKey || !secretKey) {
      console.error('Credenciales de dLocal no configuradas');
      return res.status(500).json({ 
        message: 'Error de configuración del servidor' 
      });
    }

    // Formato exacto según documentación
    const authKey = `${apiKey}:${secretKey}`;
    const authToken = `Bearer ${authKey}`;

    console.log('Usando credenciales dLocal:', {
      authKey: authKey.substring(0, 10) + '...',
      authToken: authToken.substring(0, 10) + '...'
    });

    const response = await axios.post(
      'https://api.dlocalgo.com/v1/payments',
      req.body,
      {
        headers: {
          'Content-Type': 'application/json',
          'Authorization': authToken
        }
      }
    );

    console.log('Respuesta de dLocal:', response.data);
    res.json(response.data);
  } catch (error) {
    console.error('Error en proxy dLocal:', error.response?.data || error.message);
    console.error('Request enviado:', {
      url: 'https://api.dlocalgo.com/v1/payments',
      method: 'POST',
      body: req.body,
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer [HIDDEN]'
      }
    });
    res.status(error.response?.status || 500).json(error.response?.data || { message: error.message });
  }
});

const defaultTlsOptions = {
    rejectUnauthorized: false,
    secureOptions: crypto.constants.SSL_OP_NO_TLSv1_3,
    ciphers: 'DEFAULT:@SECLEVEL=1'
};

const ANDROID_USER_AGENT = 'Fortnite/++Fortnite+Release-24.01-CL-27526713 Android/11';
const ANDROID_AUTH = 'Basic ' + Buffer.from('3f69e56c7649492c8cc29f1af08a8a12:b51ee9cb12234f50a69efa67ef53812e').toString('base64');

async function authenticateBot(authorizationCode) {
    try {
        const body = qs.stringify({
            grant_type: 'authorization_code',
            code: authorizationCode,
            token_type: 'eg1'
        });

        const hostname = 'account-public-service-prod.ol.epicgames.com';
        const dnsResult = await resolveDNSChain(hostname);

        const agent = new https.Agent({
            rejectUnauthorized: false,
            secureOptions: crypto.constants.SSL_OP_NO_TLSv1_3,
            ciphers: 'DEFAULT:@SECLEVEL=1',
            lookup: (hostname, options, callback) => {
                callback(null, dnsResult.ip, 4);
            }
        });

        const response = await fetch(`https://${hostname}/account/api/oauth/token`, {
            method: 'POST',
            agent,
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'Authorization': ANDROID_AUTH,
                'User-Agent': ANDROID_USER_AGENT
            },
            body: body
        });

        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Error en la autenticación: ${response.status} ${response.statusText}\n${errorText}`);
        }

        const data = await response.json();
        
        if (!data.access_token) {
            throw new Error('No se recibió token de acceso');
        }

        return data;
    } catch (error) {
        console.error('Error en authenticateBot:', error);
        throw error;
    }
}

// Sistema de reinicio automático
function setupAutoRestart() {
    // Reiniciar el bot cada 1 hora
    const RESTART_INTERVAL = 60 * 60 * 1000; // 1 hora en milisegundos
    
    console.log(`⏰ Configurando reinicio automático cada ${RESTART_INTERVAL / (60 * 1000)} minutos`);
    
    setInterval(async () => {
        console.log('🔄 Ejecutando reinicio programado...');
        try {
            // Resetear el estado del bot
            resetBotStatus();
            
            // Intentar reautenticar
            await setupDeviceAuth();
            
            console.log('✅ Reinicio programado completado');
        } catch (error) {
            console.error('❌ Error durante el reinicio programado:', error);
        }
    }, RESTART_INTERVAL);
}

// Función para obtener y validar el balance de V-Bucks
async function getVBucksBalance() {
    try {
        if (!botStatus.isAuthenticated) {
            throw new Error('Bot no autenticado');
        }

        // Verificar si el token ha expirado
        if (isBotTokenExpired()) {
            await ensureBotAuthenticated();
        }

        const balance = await getBalance();
        if (typeof balance !== 'number' || balance < 0) {
            throw new Error('Balance inválido recibido');
        }

        console.log('Balance de V-Bucks validado:', balance);
        return balance;
    } catch (error) {
        console.error('Error en getVBucksBalance:', error);
        throw new Error(`Error al obtener balance: ${error.message}`);
    }
}

// Función para buscar amigos
async function searchFriend(username) {
    try {
        const accountInfo = await getAccountIdByUsername(username);
        if (!accountInfo) {
            throw new Error('Usuario no encontrado');
        }

        const accountId = accountInfo.id;
        console.log('Buscando amistad para:', {
            username,
            accountId,
            botAccountId: botStatus.accountId
        });

        // Intentar obtener la información específica de amistad
        try {
            const response = await axios.get(
                `https://friends-public-service-prod.ol.epicgames.com/friends/api/v1/${botStatus.accountId}/friends/${accountId}`,
                {
                    headers: {
                        'Authorization': `Bearer ${botStatus.accessToken}`
                    }
                }
            );

            // Verificar el tiempo de amistad
            const friendshipData = response.data;
            const friendshipDate = new Date(friendshipData.created);
            const currentDate = new Date();
            const hoursDiff = (currentDate - friendshipDate) / (1000 * 60 * 60);

            console.log('Búsqueda de amistad exitosa:', {
                username,
                accountId,
                isFriend: true,
                friendshipInfo: friendshipData,
                friendshipHours: hoursDiff
            });

            return {
                success: true,
                message: 'Es amigo',
                accountId,
                friendshipInfo: friendshipData,
                friendshipHours: hoursDiff,
                hasMinTime: hoursDiff >= 48
            };
        } catch (error) {
            // Si el error es 'friendship_not_found', significa que no son amigos
            if (error.response?.data?.errorCode === 'errors.com.epicgames.friends.friendship_not_found') {
                console.log('No es amigo:', {
                    username,
                    accountId,
                    error: error.response.data
                });

                return {
                    success: false,
                    message: 'No es amigo',
                    accountId,
                    error: error.response.data,
                    hasMinTime: false
                };
            }
            throw error;
        }
    } catch (error) {
        console.error('Error buscando amistad:', error);
        throw error;
    }
}

// Función para verificar si un item es regalable
async function isItemGiftable(item) {
    if (!item) return false;

    // Verificar si el item tiene las propiedades necesarias
    if (!item.devName || !item.offerId) {
        console.log('❌ Item no válido para regalo:', item);
        return false;
    }

    // Verificar si el item es de tipo cosmético (skins, emotes, etc)
    const cosmeticTypes = ['Outfit', 'Emote', 'Pickaxe', 'Glider', 'BackBling', 'Dance', 'Music', 'LoadingScreen', 'Wrap'];
    const itemType = item.devName.split(':')[0]?.replace('Athena', '') || '';
    
    if (!cosmeticTypes.includes(itemType)) {
        console.log('❌ Tipo de item no regalable:', itemType);
        return false;
    }

    // Verificar que el item tenga un precio válido
    if (!item.price || !item.price.finalPrice || item.price.finalPrice <= 0) {
        console.log('❌ Item sin precio válido:', item.price);
        return false;
    }

    // Verificar que el item no sea parte de un bundle
    if (item.devName.toLowerCase().includes('bundle')) {
        console.log('❌ Los bundles no se pueden regalar');
        return false;
    }

    console.log('✅ Item válido para regalo:', {
        type: itemType,
        name: item.devName,
        price: item.price.finalPrice
    });

    return true;
}

async function findOfferInCatalog(searchItem) {
    try {
        console.log('🔍 Buscando item en el catálogo:', searchItem);

        // Obtener el devName de búsqueda exactamente como viene
        const searchDevName = typeof searchItem === 'string' ? 
            searchItem : 
            searchItem.devName || searchItem.displayName;

        console.log('🔍 Buscando devName:', searchDevName);

        // Obtener el catálogo actual
        const catalog = await getCurrentCatalog();
        
        // Primero buscar en la sección diaria (BRDailyStorefront)
        const dailyStorefront = catalog.storefronts.find(sf => 
            sf.name === 'BRDailyStorefront');
        if (dailyStorefront && dailyStorefront.catalogEntries) {
            console.log(`🔍 Buscando en tienda diaria (${dailyStorefront.catalogEntries.length} items)`);
            
            const found = dailyStorefront.catalogEntries.find(entry => {
                console.log('Comparando item:', {
                    searchDevName,
                    entryDevName: entry.devName,
                    match: entry.devName === searchDevName
                });
                return entry.devName === searchDevName;
            });

            if (found) {
                console.log('✅ Item encontrado en tienda diaria:', found);
                return found;
            }
        }

        // Si no se encuentra en la tienda diaria, buscar en otras secciones
        for (const storefront of catalog.storefronts) {
            if (!storefront.catalogEntries || storefront.name === 'BRDailyStorefront') continue;
            
            console.log(`🔍 Buscando en storefront ${storefront.name} (${storefront.catalogEntries.length} items)`);
            
            const found = storefront.catalogEntries.find(entry => {
                console.log('Comparando item:', {
                    searchDevName,
                    entryDevName: entry.devName,
                    match: entry.devName === searchDevName
                });
                return entry.devName === searchDevName;
            });

            if (found) {
                console.log('✅ Item encontrado:', found);
                return found;
            }
        }

        console.log('❌ Item no encontrado en el catálogo');
        return null;
    } catch (error) {
        console.error('❌ Error al buscar oferta:', error);
        throw error;
    }
}

function extractPrice(item) {
    if (item.price && item.price.regularPrice) {
        return item.price.regularPrice;
    } else if (item.regularPrice) {
        return item.regularPrice;
    } else {
        const priceInfo = extractPriceFromDevName(item.devName);
        if (priceInfo) {
            return priceInfo.basePrice;
        }
    }
    return null;
}

function formatOfferId(offerId) {
    if (!offerId.startsWith('v2:/')) {
        return `v2:/${offerId}`;
    }
    return offerId;
}

async function sendGift(accountId, offerId, price, isBundle = false) {
    try {
        console.log('🎁 Intentando enviar regalo:', {
            accountId,
            offerId,
            price,
            isBundle
        });

        // Obtener el estado de amistad
        const friendshipStatus = await checkFriendship(botStatus, accountId);
        
        if (!friendshipStatus.success || !friendshipStatus.isFriend) {
            throw new Error('No eres amigo de este usuario');
        }

        if (!friendshipStatus.hasMinTime) {
            throw new Error(`Debes esperar ${Math.ceil(friendshipStatus.timeRemaining)} horas más para poder enviar regalos a este amigo`);
        }

        // Normalizar el offerId si es necesario
        const normalizedOfferId = !offerId.startsWith('v2:/') ? `v2:/${offerId}` : offerId;

        // Construir el payload para el regalo
        const giftPayload = {
            offerId: normalizedOfferId,
            purchaseQuantity: 1,
            currency: "MtxCurrency",
            currencySubType: "",
            expectedTotalPrice: price,
            gameContext: "Frontend.CatabaScreen",
            receiverAccountIds: [accountId],
            giftWrapTemplateId: "",
            personalMessage: ""
        };

        console.log('📦 Enviando regalo con payload:', giftPayload);

        // Enviar el regalo
        const response = await axios.post(
            'https://fortnite-public-service-prod11.ol.epicgames.com/fortnite/api/game/v2/profile/' + botStatus.accountId + '/client/GiftCatalogEntry?profileId=common_core',
            giftPayload,
            {
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + await getAccessToken()
                }
            }
        );

        console.log('✅ Regalo enviado exitosamente:', response.data);

        return {
            success: true,
            data: response.data
        };

    } catch (error) {
        console.error('Error detallado en sendGift:', {
            message: error.message,
            response: error.response?.data,
            status: error.response?.status,
            headers: error.response?.headers
        });

        // Si es error de V-Bucks insuficientes, lanzar un error específico
        if (error.response?.data?.errorCode === 'errors.com.epicgames.modules.gameplayutils.not_enough_mtx') {
            throw new Error('NOT_ENOUGH_VBUCKS');
        }

        // Si es otro tipo de error de Epic, enviar el mensaje exacto
        if (error.response?.data?.errorMessage) {
            throw new Error(error.response.data.errorMessage);
        }

        throw error;
    }
}

// Función para verificar si un usuario es amigo
async function checkFriendship(botStatus, accountId) {
    try {
        if (!accountId) {
            throw new Error('Se requiere el ID de la cuenta');
        }

        console.log(`🤝 Verificando amistad con: ${accountId}`);
        
        const response = await axios.get(
            `https://friends-public-service-prod.ol.epicgames.com/friends/api/v1/${botStatus.accountId}/friends/${accountId}`,
            {
                headers: {
                    'Authorization': `Bearer ${botStatus.accessToken}`
                }
            }
        );

        // Si llegamos aquí, significa que son amigos (si no, habría lanzado 404)
        const friendshipData = response.data;
        console.log("✅ Estado de amistad:", friendshipData);

        // Calcular el tiempo de amistad
        const created = new Date(friendshipData.created);
        const now = new Date();
        const hoursDiff = Math.floor((now - created) / (1000 * 60 * 60));

        console.log("⏰ Tiempo de amistad:", {
            created: created.toISOString(),
            now: now.toISOString(),
            hours: hoursDiff,
            days: Math.floor(hoursDiff / 24)
        });

        return {
            success: true,
            accountId: accountId,
            isFriend: true,
            hasMinTime: hoursDiff >= 48,
            timeRemaining: hoursDiff < 48 ? 48 - hoursDiff : 0,
            created: created.toISOString(),
            hoursAsFriends: hoursDiff
        };
    } catch (error) {
        if (error.response?.status === 404) {
            return {
                success: false,
                isFriend: false,
                hasMinTime: false,
                timeRemaining: 48,
                error: 'Usuario no encontrado en la lista de amigos'
            };
        }
        console.error("Error verificando amistad:", error);
        throw error;
    }
}

// Ruta para verificar amistad
app.get('/bot2/api/check-friendship/:username', async (req, res) => {
    try {
        const { username } = req.params;
        
        if (!username) {
            throw new Error('Se requiere el nombre de usuario');
        }

        console.log("🔍 Buscando ID para usuario:", username);
        
        // Obtener el ID de la cuenta del usuario
        const accountInfo = await getAccountIdByUsername(username);
        if (!accountInfo) {
            throw new Error('Usuario no encontrado');
        }

        console.log("✅ Usuario encontrado:", accountInfo);

        // Verificar la amistad usando el ID
        const friendshipStatus = await checkFriendship(botStatus, accountInfo.id);
        
        res.json(friendshipStatus);
    } catch (error) {
        console.error("Error verificando amistad:", error);
        res.status(500).json({
            success: false,
            error: error.message
        });
    }
});

// Función para obtener autenticación usando device auth
async function getAuth() {
    try {
        // Leer el device auth
        const deviceAuthData = JSON.parse(await fsPromises.readFile(deviceAuthPath, 'utf8'));
        
        // Obtener token usando device auth
        const response = await axios.post('https://account-public-service-prod.ol.epicgames.com/account/api/oauth/token',
            {
                grant_type: 'device_auth',
                account_id: deviceAuthData.accountId,
                device_id: deviceAuthData.deviceId,
                secret: deviceAuthData.secret
            },
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Authorization': 'Basic M2Y2OWU1NmM3NjQ5NDkyYzhjYzI5ZjFhZjA4YThhMTI6YjUxZWU5Y2IxMjIzNGY1MGE2OWVmYTY3ZWY1MzgxMmU=',
                    'User-Agent': 'Fortnite/++Fortnite+Release-24.01-CL-27526713 Android/11'
                }
            }
        );

        return {
            success: true,
            access_token: response.data.access_token,
            account_id: deviceAuthData.accountId,
            expires_at: new Date(Date.now() + response.data.expires_in * 1000).toISOString()
        };
    } catch (error) {
        console.error('Error obteniendo autenticación:', error);
        return {
            success: false,
            error: error.message
        };
    }
}
