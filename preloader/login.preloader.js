const {
    contextBridge,
    ipcRenderer,
} = require("electron");
const crypto = require('crypto');


contextBridge.exposeInMainWorld(
    "bridge", {
        send: (channel, ...args) => {
            let validChannels = ['login:init','app:quit'];
            if (validChannels.includes(channel)) {
                ipcRenderer.send(channel, ...args);
            }
        },
        receive: (channel, func) => {
            let validChannels = [];
            if (validChannels.includes(channel)) {
                ipcRenderer.on(channel, (event, ...args) => func(...args));
            }
        },
        sha512hash: (value) => {
            return crypto.createHash('sha512','salty')
            .update(value) 
            .digest('base64');
        }
    }
);