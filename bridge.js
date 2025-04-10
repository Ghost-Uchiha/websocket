const WebSocket = require('ws');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const http = require('http');

const clientSecrets = 'hadron';
const JWT_SECRET = 'iriswallet';
const PORT = process.env.PORT || 8080;

const sessions = {}; // sessionId => { userId, hadron, iris }

const server = http.createServer();
const wss = new WebSocket.Server({ server });

function verifySignature(payload, signatureHex, secret) {
  const hmac = crypto.createHmac('sha256', secret);
  hmac.update(JSON.stringify(payload));
  const expectedSignature = hmac.digest();
  const receivedSignature = Buffer.from(signatureHex, 'hex');

  if (expectedSignature.length !== receivedSignature.length) return false;
  return crypto.timingSafeEqual(expectedSignature, receivedSignature);
}

function send(ws, msg) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(msg));
  }
}

wss.on('connection', (ws, req) => {
  const host = req.headers.host;
  const protocol = req.headers['x-forwarded-proto'] || 'ws';
  const baseUrl = `${protocol}://${host}`;

  console.log('🔌 Client connected');

  ws.on('message', (raw) => {
    try {
      const msg = JSON.parse(raw);
      console.log('📩 Received message:', msg);

      const secret = clientSecrets;

      if (msg.type === 'session_init') {
        const payload = {
          type: 'session_init',
          userId: msg.userId,
          timestamp: msg.timestamp,
          nonce: msg.nonce
        };

        if (!secret || !verifySignature(payload, msg.signature, secret)) {
          console.log('❌ Invalid signature for session_init');
          return send(ws, { error: 'Invalid signature' });
        }

        const sessionId = crypto.randomUUID();
        const connectionUrl = `${protocol === 'https' ? 'wss' : 'ws'}://${host}`;
        const connectionPayload = { sessionId, userId: msg.userId, connectionUrl };

        const hmacConnect = crypto.createHmac('sha256', secret);
        hmacConnect.update(JSON.stringify({ type: 'iris_connect', ...connectionPayload }));
        const connectionSignature = hmacConnect.digest('hex');

        const token = jwt.sign(
          { ...connectionPayload, signature: connectionSignature },
          JWT_SECRET,
          { expiresIn: '1h' }
        );

        sessions[sessionId] = { userId: msg.userId, hadron: ws, iris: null };
        ws.sessionId = sessionId;
        ws.role = 'hadron'; // ✅ Identify sender
        send(ws, { type: 'session_created', jwt: token });

      } else if (msg.type === 'iris_connect') {
        const payload = {
          type: 'iris_connect',
          sessionId: msg.sessionId,
          userId: msg.userId,
          connectionUrl: msg.connectionUrl
        };

        if (!secret || !verifySignature(payload, msg.signature, secret)) {
          console.log('❌ Invalid signature for iris_connect');
          return send(ws, { error: 'Invalid signature' });
        }

        const session = sessions[msg.sessionId];
        if (!session) {
          console.log('❌ Session not found for iris_connect');
          return send(ws, { error: 'Session not found' });
        }

        if (session.iris) {
          console.log('⚠️ IrisWallet already connected');
          return send(ws, { error: 'IrisWallet already connected to this session' }); // ✅
        }

        session.iris = ws;
        ws.sessionId = msg.sessionId;
        ws.role = 'iris'; // ✅

        send(session.hadron, { type: 'iris_connected', sessionId: msg.sessionId });
        send(ws, { type: 'connected_ack', sessionId: msg.sessionId });

      } else if (
        msg.type === 'wallet_op_request' ||
        msg.type === 'wallet_op_response' ||
        msg.type === 'message' ||
        msg.type === 'send_btc'
      ) {
        const session = sessions[msg.sessionId];
        if (!session) {
          console.log(`❌ Session not found for ${msg.type}`);
          return;
        }
        else{
          send(ws,msg)
        }

        const target = msg.sender === 'hadron' ? session.iris : session.hadron;
        if (target) {
          send(target, msg);
        } else {
          console.log(`❌ Target not connected for ${msg.type}`);
        }
      }
      

    } catch (e) {
      console.error('❌ Error:', e.message);
      send(ws, { error: 'Invalid message format' });
    }
  });

  ws.on('close', () => {
    console.log('❎ Client disconnected');
    const session = sessions[ws.sessionId];
    if (session) {
      const counterpart =
        ws.role === 'hadron' ? session.iris : session.hadron;

      // Notify the other party ✅
      send(counterpart, {
        type: 'disconnect_notice',
        role: ws.role,
        sessionId: ws.sessionId
      });

      // Clear the disconnected socket
      if (ws.role === 'hadron') session.hadron = null;
      if (ws.role === 'iris') session.iris = null;

      // If both disconnected, remove session ✅
      if (!session.hadron && !session.iris) {
        delete sessions[ws.sessionId];
        console.log(`🗑️ Session ${ws.sessionId} deleted`);
      }
    }
  });
});

server.listen(PORT, () => {
  console.log(`🚀 Bridge WebSocket server running on port ${PORT}`);
});
