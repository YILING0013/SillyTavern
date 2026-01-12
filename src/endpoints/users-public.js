import crypto from 'node:crypto';

import storage from 'node-persist';
import express from 'express';
import lodash from 'lodash';
import { RateLimiterMemory, RateLimiterRes } from 'rate-limiter-flexible';
import { getIpFromRequest, getRealIpFromHeader } from '../express-common.js';
import { color, Cache, getConfigValue } from '../util.js';
import { checkForNewContent, CONTENT_TYPES } from './content-manager.js';
import {
    KEY_PREFIX,
    getUserAvatar,
    toKey,
    getPasswordHash,
    getPasswordSalt,
    getAllUserHandles,
    ensurePublicDirectoriesExist,
    getUserDirectories,
} from '../users.js';

const DISCREET_LOGIN = getConfigValue('enableDiscreetLogin', false, 'boolean');
const PREFER_REAL_IP_HEADER = getConfigValue('rateLimiting.preferRealIpHeader', false, 'boolean');
const MFA_CACHE = new Cache(5 * 60 * 1000);

const AFDIAN_USER_ID = getConfigValue('afdian.userId') || '';
const AFDIAN_TOKEN = getConfigValue('afdian.apiToken') || '';

const getIpAddress = (request) => PREFER_REAL_IP_HEADER ? getRealIpFromHeader(request) : getIpFromRequest(request);

export const router = express.Router();
const loginLimiter = new RateLimiterMemory({
    points: 5,
    duration: 60,
});
const recoverLimiter = new RateLimiterMemory({
    points: 5,
    duration: 300,
});
const signupLimiter = new RateLimiterMemory({
    points: 5,
    duration: 3600, // Strict limit: 5 signups per hour
});

/**
 * Creates a signature for the Afdian API.
 * @param {string} token API Token
 * @param {object} params Request parameters
 * @param {number} ts Timestamp
 * @param {string} userId User ID
 * @returns {string} MD5 Signature
 */
function createAfdianSignature(token, params, ts, userId) {
    const paramsJson = JSON.stringify(params);
    const signStr = `${token}params${paramsJson}ts${ts}user_id${userId}`;
    return crypto.createHash('md5').update(signStr).digest('hex');
}

/**
 * Verifies an order with the Afdian API.
 * @param {string} userId The user ID to verify
 * @param {string} orderId The order ID to verify
 * @returns {Promise<{valid: boolean, error?: string}>} Verification result
 */
async function verifyAfdianOrder(userId, orderId) {
    try {
        const url = 'https://afdian.com/api/open/query-order';
        const params = { out_trade_no: orderId };
        const ts = Math.floor(Date.now() / 1000);
        const sign = createAfdianSignature(AFDIAN_TOKEN, params, ts, AFDIAN_USER_ID);

        const payload = {
            user_id: AFDIAN_USER_ID,
            params: JSON.stringify(params),
            ts: ts,
            sign: sign,
        };

        const response = await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(payload),
        });

        const data = await response.json();

        if (data.ec !== 200) {
            return { valid: false, error: 'Afdian API error: ' + data.em };
        }

        const orderList = data.data?.list;
        if (!orderList || orderList.length === 0) {
            return { valid: false, error: 'Order not found' };
        }

        const order = orderList[0];

        // 1. Verify User ID Match
        if (order.user_id !== userId) {
            return { valid: false, error: 'User ID does not match order' };
        }

        // 2. Verify Amount (>= 10)
        const totalAmount = parseFloat(order.total_amount);
        if (isNaN(totalAmount) || totalAmount < 10) {
            return { valid: false, error: 'Order amount insufficient' };
        }

        return { valid: true };

    } catch (error) {
        console.error('Verify Afdian order failed:', error);
        return { valid: false, error: 'Internal verification error' };
    }
}

router.post('/list', async (_request, response) => {
    try {
        if (DISCREET_LOGIN) {
            return response.sendStatus(204);
        }

        /** @type {import('../users.js').User[]} */
        const users = await storage.values(x => x.key.startsWith(KEY_PREFIX));

        /** @type {Promise<import('../users.js').UserViewModel>[]} */
        const viewModelPromises = users
            .filter(x => x.enabled)
            .map(user => new Promise(async (resolve) => {
                getUserAvatar(user.handle).then(avatar =>
                    resolve({
                        handle: user.handle,
                        name: user.name,
                        created: user.created,
                        avatar: avatar,
                        password: !!user.password,
                    }),
                );
            }));

        const viewModels = await Promise.all(viewModelPromises);
        viewModels.sort((x, y) => (x.created ?? 0) - (y.created ?? 0));
        return response.json(viewModels);
    } catch (error) {
        console.error('User list failed:', error);
        return response.sendStatus(500);
    }
});

router.post('/login', async (request, response) => {
    try {
        if (!request.body.handle) {
            console.warn('Login failed: Missing required fields');
            return response.status(400).json({ error: 'Missing required fields' });
        }

        const ip = getIpAddress(request);
        await loginLimiter.consume(ip);

        /** @type {import('../users.js').User} */
        const user = await storage.getItem(toKey(request.body.handle));

        if (!user) {
            console.error('Login failed: User', request.body.handle, 'not found');
            return response.status(403).json({ error: 'Incorrect credentials' });
        }

        if (!user.enabled) {
            console.warn('Login failed: User', user.handle, 'is disabled');
            return response.status(403).json({ error: 'User is disabled' });
        }

        if (user.password && user.password !== getPasswordHash(request.body.password, user.salt)) {
            console.warn('Login failed: Incorrect password for', user.handle);
            return response.status(403).json({ error: 'Incorrect credentials' });
        }

        if (!request.session) {
            console.error('Session not available');
            return response.sendStatus(500);
        }

        await loginLimiter.delete(ip);
        request.session.handle = user.handle;
        console.info('Login successful:', user.handle, 'from', ip, 'at', new Date().toLocaleString());
        return response.json({ handle: user.handle });
    } catch (error) {
        if (error instanceof RateLimiterRes) {
            console.error('Login failed: Rate limited from', getIpAddress(request));
            return response.status(429).send({ error: 'Too many attempts. Try again later or recover your password.' });
        }

        console.error('Login failed:', error);
        return response.sendStatus(500);
    }
});

router.post('/signup', async (request, response) => {
    try {
        const { userId, orderId, name, password } = request.body;

        if (!userId || !orderId || !name || !password) {
            console.warn('Signup failed: Missing required fields');
            return response.status(400).json({ error: 'Missing required fields' });
        }

        const ip = getIpAddress(request);
        await signupLimiter.consume(ip);

        // 1. Check if user already exists
        const handle = String(userId);
        const handles = await getAllUserHandles();

        if (handles.some(x => x === handle)) {
            console.warn('Signup failed: User with that handle already exists');
            return response.status(409).json({ error: 'User already exists' });
        }

        // 2. Verify with Afdian
        const verification = await verifyAfdianOrder(userId, orderId);

        if (!verification.valid) {
            console.warn('Signup verification failed for', userId, ':', verification.error);
            return response.status(400).json({ error: verification.error || 'Verification failed' });
        }

        // 3. Create User
        const salt = getPasswordSalt();
        const passwordHash = getPasswordHash(password, salt);

        const newUser = {
            handle: handle,
            name: name,
            created: Date.now(),
            password: passwordHash,
            salt: salt,
            admin: false,
            enabled: true,
        };

        await storage.setItem(toKey(handle), newUser);

        // 4. Initialize Data Directories
        console.info('Creating data directories for new user', newUser.handle);
        await ensurePublicDirectoriesExist();
        const directories = getUserDirectories(newUser.handle);
        await checkForNewContent([directories], [CONTENT_TYPES.SETTINGS]);

        await signupLimiter.delete(ip);
        console.info('Signup successful:', newUser.handle);

        return response.json({ handle: newUser.handle });

    } catch (error) {
        if (error instanceof RateLimiterRes) {
            console.error('Signup failed: Rate limited from', getIpAddress(request));
            return response.status(429).send({ error: 'Too many attempts. Try again later.' });
        }
        console.error('Signup failed:', error);
        return response.sendStatus(500);
    }
});

router.post('/recover-step1', async (request, response) => {
    try {
        if (!request.body.handle) {
            console.warn('Recover step 1 failed: Missing required fields');
            return response.status(400).json({ error: 'Missing required fields' });
        }

        const ip = getIpAddress(request);
        await recoverLimiter.consume(ip);

        /** @type {import('../users.js').User} */
        const user = await storage.getItem(toKey(request.body.handle));

        if (!user) {
            console.error('Recover step 1 failed: User', request.body.handle, 'not found');
            return response.status(404).json({ error: 'User not found' });
        }

        if (!user.enabled) {
            console.error('Recover step 1 failed: User', user.handle, 'is disabled');
            return response.status(403).json({ error: 'User is disabled' });
        }

        const mfaCode = String(crypto.randomInt(1000, 9999));
        console.log();
        console.log(color.blue(`${user.name}, your password recovery code is: `) + color.magenta(mfaCode));
        console.log();
        MFA_CACHE.set(user.handle, mfaCode);
        return response.sendStatus(204);
    } catch (error) {
        if (error instanceof RateLimiterRes) {
            console.error('Recover step 1 failed: Rate limited from', getIpAddress(request));
            return response.status(429).send({ error: 'Too many attempts. Try again later or contact your admin.' });
        }

        console.error('Recover step 1 failed:', error);
        return response.sendStatus(500);
    }
});

router.post('/recover-step2', async (request, response) => {
    try {
        if (!request.body.handle || !request.body.code) {
            console.warn('Recover step 2 failed: Missing required fields');
            return response.status(400).json({ error: 'Missing required fields' });
        }

        /** @type {import('../users.js').User} */
        const user = await storage.getItem(toKey(request.body.handle));
        const ip = getIpAddress(request);

        if (!user) {
            console.error('Recover step 2 failed: User', request.body.handle, 'not found');
            return response.status(404).json({ error: 'User not found' });
        }

        if (!user.enabled) {
            console.warn('Recover step 2 failed: User', user.handle, 'is disabled');
            return response.status(403).json({ error: 'User is disabled' });
        }

        const mfaCode = MFA_CACHE.get(user.handle);

        if (request.body.code !== mfaCode) {
            await recoverLimiter.consume(ip);
            console.warn('Recover step 2 failed: Incorrect code');
            return response.status(403).json({ error: 'Incorrect code' });
        }

        if (request.body.newPassword) {
            const salt = getPasswordSalt();
            user.password = getPasswordHash(request.body.newPassword, salt);
            user.salt = salt;
            await storage.setItem(toKey(user.handle), user);
        } else {
            user.password = '';
            user.salt = '';
            await storage.setItem(toKey(user.handle), user);
        }

        await recoverLimiter.delete(ip);
        MFA_CACHE.remove(user.handle);
        return response.sendStatus(204);
    } catch (error) {
        if (error instanceof RateLimiterRes) {
            console.error('Recover step 2 failed: Rate limited from', getIpAddress(request));
            return response.status(429).send({ error: 'Too many attempts. Try again later or contact your admin.' });
        }

        console.error('Recover step 2 failed:', error);
        return response.sendStatus(500);
    }
});
