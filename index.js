const electron = require("electron");
const { app, BrowserWindow, ipcMain } = electron;
const url = require("url");
const cryptoTask = require("./modules/aes-rsa");
let loginHash = "";
let mainWindow;

app.on("ready", () => {
  let loginWindow = new BrowserWindow({
    width: 500,
    height: 150,
    webPreferences: {
      nodeIntegration: false,
      devTools: false,
      preload: app.getAppPath() + '/preloader/login.preloader.js',
      contextIsolation: true,
      enableRemoteModule: false,
    },
    frame: false,
    alwaysOnTop: false,
    resizable: false,
    show: false,
  });
  loginWindow.loadURL(
    url.format({
      pathname: app.getAppPath() + "/ui/login.html",
      protocol: "file:",
      slashes: true,
    })
  );

  loginWindow.once("ready-to-show", () => {
    loginWindow.show();
  });

  loginWindow.on("closed", () => {
    loginWindow = null;
  });
});

let loadAccountMenu = () => {
  mainWindow = new BrowserWindow({
    width: 450,
    webPreferences: {
      nodeIntegration: false,
      devTools: false,
      preload: app.getAppPath() + '/preloader/accounts.preloader.js',
      contextIsolation: true,
      enableRemoteModule: false,
    },
    frame: false,
    alwaysOnTop: false,
    resizable: false,
    show: false,
  });

  mainWindow.loadURL(
    url.format({
      pathname: app.getAppPath() + "/ui/accounts.html",
      protocol: "file:",
      slashes: true,
    })
  );

  mainWindow.on("closed", () => {
    app.quit();
  });

  mainWindow.webContents.on("did-finish-load", () => {
    mainWindow.webContents.send(
      "accounts:load",
      cryptoTask.getAllAccountFiles(loginHash)
    );
  });

  mainWindow.once("ready-to-show", () => {
    mainWindow.show();
  });
};

let createAccountWindow = (load = "") => {
  let accountWindow = new BrowserWindow({
    width: 600,
    height: 380,
    webPreferences: {
      nodeIntegration: false,
      devTools: false,
      preload: app.getAppPath() + '/preloader/account_window.preloader.js',
      contextIsolation: true,
      enableRemoteModule: false,
    },
    resizable: false,
    frame: false,
    alwaysOnTop: false,
    show: false,
  });

  accountWindow.loadURL(
    url.format({
      pathname: app.getAppPath() + "/ui/account_window.html",
      protocol: "file:",
      slashes: true,
    })
  );

  accountWindow.webContents.on("did-finish-load", () => {
    if (load !== "") {
      var result = cryptoTask.decryptData(load, loginHash);
      accountWindow.webContents.send("account:load", result, load);
    }
  });

  accountWindow.once("ready-to-show", () => {
    accountWindow.show();
  });

  accountWindow.on("closed", () => {
    accountWindow = null;
  });
};

let createOTPWindow = (load = "") => {
  let otpWindow = new BrowserWindow({
    width: 600,
    height: 335,
    webPreferences: {
      nodeIntegration: false,
      devTools: false,
      preload: app.getAppPath() + '/preloader/otp_window.preloader.js',
      contextIsolation: true,
      enableRemoteModule: false,
    },
    resizable: false,
    frame: false,
    alwaysOnTop: false,
    show: false,
  });

  otpWindow.loadURL(
    url.format({
      pathname: app.getAppPath() + "/ui/otp_window.html",
      protocol: "file:",
      slashes: true,
    })
  );

  otpWindow.webContents.on("did-finish-load", () => {
    if (load !== "") {
      var result = cryptoTask.decryptData(load, loginHash);
      otpWindow.webContents.send("otp:load", result, load);
    }
  });

  otpWindow.once("ready-to-show", () => {
    otpWindow.show();
  });

  otpWindow.on("closed", () => {
    otpWindow = null;
  });

};

ipcMain.on("login:init", (event, password, save) => {
  if (!cryptoTask.keyPairExists()) cryptoTask.generateKeyPair(password);
  else if (!cryptoTask.testPassword(password)) app.quit();
  if (save) loginHash = password;
  loadAccountMenu();
});
 
/** IPC */
ipcMain.on("account:new", () => {
  createAccountWindow();
});

ipcMain.on("account:load", (event, filename) => {
  createAccountWindow(filename);
});

ipcMain.on("account:save", (event, data) => {
  cryptoTask.encryptData(data);
  mainWindow.webContents.send(
    "accounts:load",
    cryptoTask.getAllAccountFiles(loginHash)
  );
});

ipcMain.on("account:delete", (event, file) => {
  cryptoTask.deleteAccountFile(file);
  mainWindow.webContents.send(
    "accounts:load",
    cryptoTask.getAllAccountFiles(loginHash)
  );
});

ipcMain.on("otp:new", () => {
  createOTPWindow();
});

ipcMain.on("otp:load", (event, filename) => {
  createOTPWindow(filename);
});

ipcMain.on("otp:save", (event, data) => {
  cryptoTask.encryptData(data);
  mainWindow.webContents.send(
    "accounts:load",
    cryptoTask.getAllAccountFiles(loginHash)
  );
});

ipcMain.on("otp:delete", (event, file) => {
  cryptoTask.deleteAccountFile(file);
  mainWindow.webContents.send(
    "accounts:load",
    cryptoTask.getAllAccountFiles(loginHash)
  );
});

ipcMain.on("app:quit", () => {
  app.quit();
});

/** Security fixes? */

app.on("web-contents-created", (event, contents) => {
  contents.on("will-navigate", (event, navigationUrl) => {
    event.preventDefault();
  });

  contents.on("will-attach-webview", (event, webPreferences, params) => {
    event.preventDefault();
  });
});
