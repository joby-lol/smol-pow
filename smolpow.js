/**
 * smolPoW
 * https://github.com/joby-lol/smol-pow
 * (c) 2026 Joby Elliott code@joby.lol
 * MIT License https://opensource.org/licenses/MIT
 */

const smolPoW = {
    /**
     * Run the proof of work challenge solver and redirect to target URL if successful. Sets a cookie with the solution and challenge string.
     * 
     * @param {Object} [options]
     * @param {string} [options.hash] Raw challenge string (defaults to window.location.hash)
     * @param {function(string): void} [options.onStatus] Callback for status updates passed as strings
     * @param {function(Error): void} [options.onError] Callback on failure
     * @param {function(string, string, string): void} [options.onSolve] Callback on successful solution, passed challenge, solution, and safe return URL
     * @param {boolean} [options.ignoreExpiration] Whether to ignore the expiration time of the challenge
     */
    async run(options = {}) {
        const onStatus = options.onStatus || this.defaultStatusHandler;
        const onError = options.onError || this.defaultErrorHandler;
        const onSolve = options.onSolve || this.defaultSolutionHandler;
        const ignoreExpiration = options.ignoreExpiration || false;

        try {
            // Extract challenge string from location hash or options
            let rawHash = options.hash || window.location.hash;
            if (rawHash.startsWith('#')) {
                rawHash = rawHash.slice(1);
            }
            if (!rawHash) {
                throw new Error('No challenge string provided in hash.');
            }

            // Decode Base64 JSON array
            const challengeArray = this.parseChallenge(rawHash);
            const [algo, nonce, difficulty, expiry, returnUrl] = challengeArray;

            // Check expiration
            if (!ignoreExpiration) {
                const now = Math.floor(Date.now() / 1000);
                if (now > expiry) {
                    throw new Error('Challenge has expired. Please go back and refresh retry.');
                }
            }

            // Validate return URL for safety (same-origin or relative path)
            const safeReturnUrl = this.validateReturnUrl(returnUrl);
            if (!safeReturnUrl) {
                throw new Error('Unsafe return URL specified in challenge.');
            }

            onStatus('Solving proof of work challenge...');

            // Solve the PoW puzzle
            const solution = await this.solve(algo, nonce, difficulty);

            onStatus('Challenge solved...');

            // Run solution handler
            onSolve(solution, rawHash, safeReturnUrl);

        } catch (err) {
            onError(err);
        }
    },

    /**
     * Decode and validate challenge array format.
     *
     * @param {string} base64String The base64 encoded challenge string
     * @returns {Array} The decoded challenge array
     */
    parseChallenge(base64String) {
        try {
            const jsonString = atob(base64String);
            const data = JSON.parse(jsonString);
            if (!Array.isArray(data) || data.length !== 6) {
                throw new Error('Invalid challenge array length');
            }
            return data;
        } catch (e) {
            throw new Error('Malformed challenge string: ' + e.message);
        }
    },

    /**
     * Solve the Proof of Work puzzle using standard WebCrypto API (SHA-256) inside a Web Worker.
     *
     * @param {string} algo The algorithm to use
     * @param {string} nonce The nonce to use
     * @param {number} difficulty The difficulty to use
     * @returns {Promise<string>} The solution
     */
    solve(algo, nonce, difficulty) {
        return new Promise((resolve, reject) => {
            if (typeof Worker === 'undefined') {
                reject(new Error('Web Workers are not supported in this browser.'));
                return;
            }

            const workerCode = `
self.onmessage = async function(e) {
    const { algo, nonce, difficulty } = e.data;
    if (typeof crypto === 'undefined' || !crypto.subtle) {
        self.postMessage({ error: 'WebCrypto API is not supported in this browser worker.' });
        return;
    }

    const encoder = new TextEncoder();
    const targetPrefix = '0'.repeat(difficulty);
    const chars = '0123456789abcdefghijklmnopqrstuvwxyz';

    // Helper to generate a random 8-character string
    function getRandomCandidate() {
        const randomValues = new Uint8Array(8);
        crypto.getRandomValues(randomValues);
        let result = '';
        for (let i = 0; i < 8; i++) {
            result += chars[randomValues[i] % chars.length];
        }
        return result;
    }

    while (true) {
        const candidate = getRandomCandidate();

        const inputBuffer = encoder.encode(nonce + candidate);
        const hashBuffer = await crypto.subtle.digest('SHA-256', inputBuffer);

        // Convert hash buffer to hex string
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

        if (hashHex.startsWith(targetPrefix)) {
            self.postMessage({ solution: candidate });
            return;
        }
    }
};
            `;

            let blobUrl;
            try {
                const blob = new Blob([workerCode], { type: 'application/javascript' });
                blobUrl = URL.createObjectURL(blob);
                const worker = new Worker(blobUrl);

                worker.onmessage = (e) => {
                    URL.revokeObjectURL(blobUrl);
                    worker.terminate();
                    if (e.data.error) {
                        reject(new Error(e.data.error));
                    } else {
                        resolve(e.data.solution);
                    }
                };

                worker.onerror = (err) => {
                    if (blobUrl) URL.revokeObjectURL(blobUrl);
                    worker.terminate();
                    reject(new Error('Worker error: ' + (err.message || 'Unknown error')));
                };

                worker.postMessage({ algo, nonce, difficulty });
            } catch (err) {
                if (blobUrl) URL.revokeObjectURL(blobUrl);
                reject(err);
            }
        });
    },

    /**
     * Ensure return URL is same-origin or relative path to prevent open redirects.
     * 
     * @param {string} rawUrl The raw return URL from the challenge
     * @returns {string|null} The validated return URL, or null if invalid
     */
    validateReturnUrl(rawUrl) {
        try {
            const currentOrigin = window.location.origin;
            const parsed = new URL(rawUrl, currentOrigin);
            // Block non-HTTP(S) schemes (e.g. javascript:)
            if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
                return null;
            }
            // Enforce same origin
            if (parsed.origin !== currentOrigin) {
                return null;
            }
            // Return parsed URL
            return parsed.href;
        } catch (e) {
            return null;
        }
    },

    /**
     * Default solution found callback.
     *
     * @param {string} solution The solution
     * @param {string} challengeString The raw challenge string
     * @param {string} safeReturnUrl The safe return URL
     */
    defaultSolutionHandler(solution, challengeString, safeReturnUrl) {
        console.log('[smolPoW] Solution found:', solution);
        console.log('[smolPoW] Raw hash:', challengeString);
        console.log('[smolPoW] Safe return URL:', safeReturnUrl);
        // Set cookie: smolpow=<solution>|<rawHash>
        const cookieValue = `${solution}|${challengeString}`;
        document.cookie = `${encodeURIComponent('smolpow')}=${encodeURIComponent(cookieValue)}; path=/; SameSite=Lax`;
        // Redirect back to target URL
        window.location.href = safeReturnUrl;
    },

    /**
     * Default status update UI logger. Logs to console and appends a success message to either the body or a div with the id smolpow-output.
     * 
     * @param {string} msg The status message
     */
    defaultStatusHandler(msg) {
        console.log('[smolPoW]', msg);
        const outputDiv = document.getElementById('smolpow-output');
        if (outputDiv) {
            const p = document.createElement('p');
            p.textContent = msg;
            outputDiv.appendChild(p);
        } else {
            const p = document.createElement('p');
            p.textContent = msg;
            document.body.appendChild(p);
        }
    },

    /**
     * Default error handler. Logs to console and appends an error message to either the body or a div with the id smolpow-output.
     * 
     * @param {Error} err The error to display
     */
    defaultErrorHandler(err) {
        console.error('[smolPoW Error]', err);
        const outputDiv = document.getElementById('smolpow-output');
        if (outputDiv) {
            const p = document.createElement('p');
            p.style.color = 'red';
            p.textContent = `Error: ${err.message}`;
            outputDiv.appendChild(p);
        } else {
            const p = document.createElement('p');
            p.style.color = 'red';
            p.textContent = `Error: ${err.message}`;
            document.body.appendChild(p);
        }
    }
};
