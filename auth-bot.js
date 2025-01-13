const readline = require('readline');
const fs = require('fs').promises;
const path = require('path');
const axios = require('axios');

const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

async function createDeviceAuth(authToken) {
    try {
        // Primer paso: Intercambiar el código por un token OAuth
        const response = await axios.post(
            'https://account-public-service-prod.ol.epicgames.com/account/api/oauth/token',
            `grant_type=authorization_code&code=${authToken}`,
            {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                    'Authorization': 'Basic M2Y2OWU1NmM3NjQ5NDkyYzhjYzI5ZjFhZjA4YThhMTI6YjUxZWU5Y2IxMjIzNGY1MGE2OWVmYTY3ZWY1MzgxMmU=',
                    'User-Agent': 'Fortnite/++Fortnite+Release-24.01-CL-27526713 Android/11'
                }
            }
        );

        // Segundo paso: Crear el Device Auth
        const deviceAuthResponse = await axios.post(
            'https://account-public-service-prod.ol.epicgames.com/account/api/public/account/' + response.data.account_id + '/deviceAuth',
            {},
            {
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + response.data.access_token
                }
            }
        );

        return {
            accountId: deviceAuthResponse.data.accountId,
            deviceId: deviceAuthResponse.data.deviceId,
            secret: deviceAuthResponse.data.secret
        };
    } catch (error) {
        console.error('Error:', error.message);
        if (error.response) {
            console.error('Detalles del error:', error.response.data);
        }
        throw error;
    }
}

async function main() {
    try {
        console.log('\n🤖 Proceso de creación de Device Auth');
        console.log('=====================================');

        while (true) {
            const botId = await new Promise(resolve => {
                rl.question('\n📝 Ingresa el ID del bot (ejemplo: bot2, bot3) o "salir" para terminar: ', resolve);
            });

            if (botId.toLowerCase() === 'salir') {
                console.log('\n👋 Proceso finalizado');
                break;
            }

            if (botId === 'bot1') {
                console.log('❌ No puedes modificar bot1, usa otro ID');
                continue;
            }

            const authToken = await new Promise(resolve => {
                rl.question('🔑 Ingresa el token de autorización: ', resolve);
            });

            console.log(`\n🔄 Procesando token para ${botId}...`);
            const deviceAuth = await createDeviceAuth(authToken);

            const deviceAuthPath = path.join(__dirname, `deviceAuth_${botId}.json`);
            await fs.writeFile(deviceAuthPath, JSON.stringify(deviceAuth, null, 4));

            console.log(`\n✅ Device Auth para ${botId} creado correctamente!`);
            console.log('📝 Datos guardados:');
            console.log(`   - Account ID: ${deviceAuth.accountId}`);
            console.log(`   - Device ID: ${deviceAuth.deviceId}`);
            console.log(`   - Secret: ${deviceAuth.secret}`);
            console.log(`📁 Archivo guardado en: deviceAuth_${botId}.json\n`);

            const continuar = await new Promise(resolve => {
                rl.question('¿Quieres crear otro Device Auth? (s/n): ', resolve);
            });

            if (continuar.toLowerCase() !== 's') {
                console.log('\n👋 Proceso finalizado');
                break;
            }
        }
    } catch (error) {
        console.error('\n❌ Error:', error.message);
    } finally {
        rl.close();
    }
}

console.log('🤖 Iniciando proceso de creación de Device Auth...');
main();
