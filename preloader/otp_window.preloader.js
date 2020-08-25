const { contextBridge, ipcRenderer } = require("electron");
const otp = require("otpauth");

contextBridge.exposeInMainWorld("bridge", {
  
  otpGen: (secret) => {
    let totp = new otp.TOTP({
      issuer: "1",
      label: "1",
      algorithm: "SHA1",
      digits: 6,
      period: 30,
      secret: secret.toString(),
    });
    return totp.generate();
  },

  send: (channel, ...args) => {
    let validChannels = ["otp:delete", "otp:save"];
    if (validChannels.includes(channel)) {
      ipcRenderer.send(channel, ...args);
    }
  },

  receive: (channel, func) => {
    let validChannels = ["otp:load"];
    if (validChannels.includes(channel)) {
      ipcRenderer.on(channel, (event, ...args) => {
        try {
          func(...args);
        } catch (error) {  }
      });
    }
  },
});
