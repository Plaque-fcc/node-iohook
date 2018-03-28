const NodeHookAddon = require('bindings')('node-iohook');

NodeHookAddon.startHook(event => console.log(event));
