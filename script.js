const configuration = {
    iceServers: [
        {
            urls: [
                'stun:stun.l.google.com:19302',
                'stun:stun1.l.google.com:19302',
                'stun:stun2.l.google.com:19302',
            ],
        },
    ],
};

let sess;
let secret;
let iv;
let salt;

let localStream;
let remoteStream;

function parseUrlParams() {
    const urlParams = new URLSearchParams(window.location.search);
    sess = decodeURIComponent(urlParams.get('sess'));
    secret = decodeURIComponent(urlParams.get('secret'));
    iv = urlParams.get('iv')
    salt = urlParams.get('salt')

    if (iv) {
        iv = decodeURIComponent(iv);
        iv = base64ToBytes(iv)
    }
    if (salt) {
        salt = decodeURIComponent(salt);
        salt = base64ToBytes(salt)
    }
    // console.log(sess, secret, iv, salt)
}
parseUrlParams()

async function shareScreen() {
    try {
        localStream = await navigator.mediaDevices.getDisplayMedia({
            audio: true,
            video: true
        });

        const videoElement = document.querySelector('video#localVideo');
        videoElement.srcObject = localStream;
    } catch (err) {
        console.error('Error accessing media devices.', err);
    }
}

async function makeCall() {
    sess = genId()
    secret = genId()
    iv = crypto.getRandomValues(new Uint8Array(12));
    salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await generateKey(secret, salt)

    const conn = new RTCPeerConnection(configuration);
    registerPeerConnectionListeners(conn)
    // const dataChannel = conn.createDataChannel('chat');
    localStream.getTracks().forEach(track => {
        conn.addTrack(track, localStream);
    });

    const saveCandidate = new Promise((resolve, reject) => {
        const candidates = []
        conn.addEventListener('icecandidate', async (event) => {
            try {
                if (!event.candidate) {
                    const msg = await encryptMessage(key, iv, JSON.stringify(candidates))
                    await save(sess, 'offer-candidate', msg)
                    resolve()
                    return;
                }
                candidates.push(event.candidate)
            } catch (err) {
                reject(err)
            }
        });
    })
    intervalLoad(sess, 'answer', async (encryptedCandidate) => {
        const decryptedAnswer = await decryptMessage(key, iv, encryptedCandidate)
        const answer = JSON.parse(decryptedAnswer);
        await conn.setRemoteDescription(new RTCSessionDescription(answer));

        intervalLoad(sess, 'answer-candidate', async (encryptedCandidate) => {
            const decryptedCandidate = await decryptMessage(key, iv, encryptedCandidate)
            const candidates = JSON.parse(decryptedCandidate);
            candidates.forEach((c) => {
                conn.addIceCandidate(c);
            })
        })
    })

    const offer = await conn.createOffer();
    await conn.setLocalDescription(offer);

    const msg = await encryptMessage(key, iv, JSON.stringify(offer))
    await Promise.all[saveCandidate, save(sess, 'offer', msg)]
    console.log('make a call succes')

    document.getElementById('inputOffer').value = `${window.location.origin}?sess=${encodeURIComponent(sess)}&secret=${encodeURIComponent(secret)}&iv=${encodeURIComponent(bytesToBase64(iv))}&salt=${encodeURIComponent(bytesToBase64(salt))}`
}

document.getElementById('makeCall').addEventListener('click', () => {
    makeCall()
})

document.getElementById('receiveCall').addEventListener('click', () => {
    receiveCall(sess, secret, iv, salt)
})

document.getElementById('shareScreen').addEventListener('click', () => {
    shareScreen()
})

async function receiveCall(sess, secret, iv, salt) {
    if (!sess) {
        alert("session information is required")
        return
    }
    if (!secret) {
        alert("secret is required")
        return
    }
    if (!iv) {
        alert("iv is required")
        return
    }
    if (!salt) {
        alert("iv is required")
        return
    }
    const key = await generateKey(secret, salt)

    const conn = new RTCPeerConnection(configuration);
    registerPeerConnectionListeners(conn)
    const saveCandidate = new Promise((resolve, reject) => {
        const candidates = []
        conn.addEventListener('icecandidate', async (event) => {
            try {
                if (!event.candidate) {
                    const msg = await encryptMessage(key, iv, JSON.stringify(candidates))
                    await save(sess, 'answer-candidate', msg)
                    resolve()
                    return;
                }
                candidates.push(event.candidate)
            } catch (err) {
                reject(err)
            }
        });
    })
    intervalLoad(sess, 'offer-candidate', async (encryptedCandidate) => {
        const decryptedCandidate = await decryptMessage(key, iv, encryptedCandidate)
        const candidates = JSON.parse(decryptedCandidate);
        candidates.forEach((c) => {
            conn.addIceCandidate(c);
        })
    })

    {
        const remoteVideo = document.querySelector('video#remoteVideo');
        conn.addEventListener('track', async (event) => {
            const [remoteStream] = event.streams;
            remoteVideo.srcObject = remoteStream;
        });
    }

    const encryptedOffer = await load(sess, 'offer')
    const decryptedOffer = await decryptMessage(key, iv, encryptedOffer)
    const offer = JSON.parse(decryptedOffer)

    await conn.setRemoteDescription(new RTCSessionDescription(offer));
    const answer = await conn.createAnswer();
    await conn.setLocalDescription(answer);

    const msg = await encryptMessage(key, iv, JSON.stringify(answer))
    await Promise.all[saveCandidate, save(sess, 'answer', msg)]
}

function registerPeerConnectionListeners(conn) {
    conn.addEventListener('icegatheringstatechange', () => {
        console.log(
            `ICE gathering state changed: ${conn.iceGatheringState}`);
    });

    conn.addEventListener('connectionstatechange', () => {
        console.log(`Connection state change: ${conn.connectionState}`);
    });

    conn.addEventListener('signalingstatechange', () => {
        console.log(`Signaling state change: ${conn.signalingState}`);
    });

    conn.addEventListener('iceconnectionstatechange ', () => {
        console.log(
            `ICE connection state change: ${conn.iceConnectionState}`);
    });
}

async function generateKey(secret, salt) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        enc.encode(secret),
        "PBKDF2",
        false,
        ["deriveBits", "deriveKey"],
    );
    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt,
            iterations: 100000,
            hash: "SHA-256",
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        true,
        ["encrypt", "decrypt"],
    );
}

function encryptMessage(key, iv, message) {
    const encoded = new TextEncoder().encode(message);
    return crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encoded,
    );
}

async function decryptMessage(key, iv, ciphertext) {
    const decoded = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ciphertext);
    return new TextDecoder("utf-8").decode(decoded)
}

function bytesToBase64(bytes) {
    const binString = String.fromCodePoint(...bytes);
    return btoa(binString);
}

function base64ToBytes(base64) {
    return Uint8Array.from(atob(base64), c => c.charCodeAt(0))
}

function bytesToUrlSafeBase64(bytes) {
    s = bytesToBase64(bytes)
    s = s.replaceAll('/', '')
    s = s.replaceAll('=', '')
    s = s.replaceAll('+', '')
    return s
}

function genId() {
    const u8 = crypto.getRandomValues(new Uint8Array(16));
    return bytesToUrlSafeBase64(u8)
}

async function save(id, filename, buffer) {
    const resp = await fetch(`https://filebin.net/${id}/${filename}.txt`, {
        method: "POST",
        referrerPolicy: 'no-referrer',
        body: buffer
    })
    if (!resp.ok) {
        throw new Error('create failed')
    }
}

async function load(id, filename) {
    const resp = await fetch(`https://filebin.net/${id}/${filename}.txt`)
    if (resp.status === 404) {
        throw new Error('file not found')
    }
    if (!resp.ok) {
        throw new Error('load failed')
    }
    const b = await resp.blob();
    return b.arrayBuffer();
}

function intervalLoad(id, filename, cb) {
    const intervalId = setInterval(async () => {
        try {
            const data = await load(id, filename);
            clearInterval(intervalId);
            cb(data);
        } catch (err) {
            if (err.message !== 'file not found') {
                clearInterval(intervalId);
                throw err
            }
        }
    }, 1000)
}