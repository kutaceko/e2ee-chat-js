const WebSocket = require('ws');

const url = process.env.WS_URL || 'ws://localhost:3000';
const room = process.env.WS_ROOM || 'lobby';
const name = process.env.WS_NAME || 'probe';

const ws = new WebSocket(url);
ws.on('open', () => {
  console.log('open');
  ws.send(JSON.stringify({ type: 'join', room, name }));
  setTimeout(() => ws.close(), 500);
});
ws.on('message', (m) => {
  console.log('message', m.toString());
});
ws.on('error', (e) => {
  console.error('error', e.message);
  process.exit(2);
});
ws.on('close', () => {
  console.log('close');
  process.exit(0);
});
