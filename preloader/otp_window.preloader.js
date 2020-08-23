const { contextBridge, ipcRenderer } = require("electron");
const otp = require("otpauth");

let totp;
window.onerror = () => {
  //return true;
};
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
        } catch (error) {
          //very weird bug if the secret starts with a number, the string splits and the otpGen is executed
          //2 or more times with the argument "secret" becoming (number) and (string)
          //console log looks like "1BSWY3DPEHPK3PXP"
          //1 invalid argument
          //BSWY3DPEHPK3PXP 1 found at (where otpGen was called)
        }
      });
    }
  },
});
