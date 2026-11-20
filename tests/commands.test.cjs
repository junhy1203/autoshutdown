// Exercise the command router from both served pages without contacting either backend.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

(async () => {
    for (const entry of ['index.html', 'dashboard.html']) {
        const html = fs.readFileSync(path.join(__dirname, '..', entry), 'utf8');
        const start = html.indexOf('async function writeCommandToDB');
        const end = html.indexOf('function triggerCommandAll', start);
        const calls = [];
        const socket = { readyState: 1, send: data => calls.push(['ws', JSON.parse(data).payload]) };
        const database = {
            ref: target => ({
                push: body => calls.push(['push', JSON.parse(JSON.stringify(body)), target]),
                set: body => calls.push(['set', JSON.parse(JSON.stringify(body)), target])
            })
        };
        const context = {
            _checkAuthPermission: async () => true,
            _fbAuth: null,
            serverTimeOffset: 9_000,
            Date: { now: () => 1_000 },
            window: { _serverMode: 'custom', _customWs: socket },
            WebSocket: { OPEN: 1 },
            firebase: { database: () => database }
        };
        const send = vm.runInNewContext(html.slice(start, end) + '\nwriteCommandToDB', context);
        assert.equal((await send('pc', 'minimize_window', { hwnd: 123 })).success, true);
        assert.equal((await send('__ALL__', 'unlock_screen')).success, true);
        assert.equal((await send('pc', 'remote_input', { input_type: 'mouse_move' })).success, true);
        socket.readyState = 3;
        assert.equal((await send('pc', 'remote_input', { input_type: 'mouse_move' })).success, true);
        assert.deepEqual(calls.map(([method, body, target]) => [method, body.action, body.timestamp, target]), [
            ['push', 'minimize_window', 10, '/commands/pc'],
            ['set', 'unlock_screen', 10, '/commands/__ALL__'],
            ['ws', 'remote_input', 10, undefined],
            ['push', 'remote_input', 10, '/commands/pc']
        ]);
    }
    console.log('Command routing passed for both dashboard entry points.');
})().catch(error => {
    console.error(error);
    process.exitCode = 1;
});
