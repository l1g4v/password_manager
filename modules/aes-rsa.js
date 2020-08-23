const crypto = require("crypto");
const fs = require("fs");
const dataLocation = (process.env.PORTABLE_EXECUTABLE_DIR || __dirname) + "/data/";

const KEY_LENGTH = 32;
const KEY_ITERATIONS = 15000;
const KEY_DIGEST = "sha512";
const AES_IV_SIZE = 16;
const KEY_TEST_MSG = "if you can read this, congrats!";

/**
 * Create a new account object
 * @param name String the account name
 * @param username String the account username (if available)
 * @param email String the account email (if available)
 * @param password String the account password
 * @returns Object
 */
exports.accountObject = (name, username = "", email = "", password = "") => {
  return {
    name: name,
    username: username,
    email: email,
    password: password,
  };
};

exports.keyPairExists = () => {
  return (
    fs.existsSync(`${dataLocation}private`) &&
    fs.existsSync(`${dataLocation}public`) &&
    fs.existsSync(`${dataLocation}test`)
  );
};
exports.testPassword = (password) => {
  try {
    var testBuffer = fs.readFileSync(`${dataLocation}test`);
    var decrypted = crypto.privateDecrypt(
      { key: this.readPrivateKey(), passphrase: password },
      testBuffer
    );
    return decrypted.toString("utf-8") === KEY_TEST_MSG;
  } catch (e) {
    return false;
  }
};

/**
 * Generate a RSA key pair and save them in files
 * @param passphrase String the private key password
 */
exports.generateKeyPair = (passphrase) => {
  if (!fs.existsSync(dataLocation)) fs.mkdirSync(dataLocation);

  var { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
    modulusLength: 4096,
    publicKeyEncoding: {
      type: "spki",
      format: "pem",
    },
    privateKeyEncoding: {
      type: "pkcs8",
      format: "pem",
      cipher: "aes-256-cbc",
      passphrase: passphrase,
    },
  });
  var testFile = crypto.publicEncrypt(publicKey, Buffer.from(KEY_TEST_MSG));
  fs.writeFile(`${dataLocation}test`, testFile, (err) => {
    if (err) console.log(err);
  });
  fs.writeFile(`${dataLocation}private`, privateKey, (err) => {
    if (err) console.log(err);
  });
  fs.writeFile(`${dataLocation}public`, publicKey, (err) => {
    if (err) console.log(err);
  });
};

/**
 * Read the RSA public key file
 * @returns String
 */
exports.readPublicKey = () => {
  return fs.readFileSync(`${dataLocation}public`, "utf8");
};
/**
 * Read the RSA private key file
 * @returns String
 */
exports.readPrivateKey = () => {
  return fs.readFileSync(`${dataLocation}private`, "utf8");
};

/**
 * Very simple decryption from a filename
 * @param filename String the filename
 * @returns String the decrypted name
 */
exports.getAccountName = (filename, passphrase) => {
  var privateKey = this.readPrivateKey();
  var keyBuffer = fs.readFileSync(`${dataLocation}${filename}.key`);

  var encryptedKey = keyBuffer.slice(AES_IV_SIZE, keyBuffer.length);

  //decrypt the encryption key
  var encryptKey = crypto.privateDecrypt(
    { key: privateKey, passphrase: passphrase },
    encryptedKey
  );

  return unsafeAESd(filename, encryptKey);
};

/**
 * Reads all data directory and returns the accounts
 * filenames
 * @returns String[] the account filenames
 */
exports.getAllAccountFiles = (password) => {
  var filename = fs.readdirSync(dataLocation);
  var fileNames = [];
  //if(filename.length == 3) return [];
  for (var i = 0; i < filename.length; i++)
    if (
      filename[i].indexOf(".key") === -1 &&
      filename[i] != "public" &&
      filename[i] != "private" &&
      filename[i] != "test"
    )
      fileNames.push({
        filename: filename[i].replace(".crypto", ""),
        decrypted: this.getAccountName(
          filename[i].replace(".crypto", ""),
          password
        ),
      });
  return fileNames;
};

/**
 * Deletes an account crypto and key data
 * @param filename String
 */
exports.deleteAccountFile = (filename) => {
  fs.unlinkSync(`${dataLocation}${filename}.key`);
  fs.unlinkSync(`${dataLocation}${filename}.crypto`);
};

/**
 * Encrypts an account and saves it to a file
 * @param data {Object}
 */
exports.encryptData = (data) => {
  //load the public key
  var publicKey = this.readPublicKey();

  //generate an encryption key and encrypt it with the RSA key
  var encryptKey = crypto.pbkdf2Sync(
    crypto.randomBytes(32),
    crypto.randomBytes(32),
    KEY_ITERATIONS,
    KEY_LENGTH,
    KEY_DIGEST
  );
  var encryptedKey = crypto.publicEncrypt(publicKey, encryptKey);

  //generate the filename by encrypting the account name
  var filename = unsafeAESe(data.name, encryptKey);

  if (
    fs.existsSync(`${dataLocation}${filename}.key`) ||
    fs.existsSync(`${dataLocation}${filename}.crypto`)
  )
    return false;

  //encrypt the file using the previous generated key then merge the IV and encrypted key
  //to a single buffer
  var encryptResult = aesEncrypt(encryptKey, JSON.stringify(data));

  var bufferKeyWrite = Buffer.concat([encryptResult.iv, encryptedKey]);
  //console.log(encryptResult.encrypted.toString('hex'));

  //save the IV and encrypted key in one file and the encrypted data in another :)
  fs.writeFileSync(`${dataLocation}${filename}.key`, bufferKeyWrite);
  fs.writeFileSync(
    `${dataLocation}${filename}.crypto`,
    encryptResult.encrypted
  );
};

/**
 * Decrypts an account file
 * @param filename String the filename
 * @param passphrase String the private key decrypt password
 * @returns {accountObject}
 */
exports.decryptData = (filename, passphrase) => {
  //load private key and account files
  var privateKey = this.readPrivateKey();
  var keyBuffer = fs.readFileSync(`${dataLocation}${filename}.key`);
  var dataBuffer = fs.readFileSync(`${dataLocation}${filename}.crypto`);

  //separate the encrypted key from the file IV
  var nonce = keyBuffer.slice(0, AES_IV_SIZE);
  var encryptedKey = keyBuffer.slice(AES_IV_SIZE, keyBuffer.length);

  //decrypt the encryption key and use it to decrypt the account data file //#DANGER
  var encryptKey = crypto.privateDecrypt(
    { key: privateKey, passphrase: passphrase },
    encryptedKey
  );
  var decrypted = aesDecrypt(encryptKey, Buffer.from(dataBuffer, "hex"), nonce);

  //return the account object
  return JSON.parse(decrypted.toString("utf-8"));
};

//Just a simple aes encrypt function that returns the IV and encrypted data
function aesEncrypt(key, data) {
  var IV = crypto.randomBytes(AES_IV_SIZE);
  var validKey = Buffer.from(key);
  var cipher = crypto.createCipheriv("aes-256-cbc", validKey, IV);
  return {
    iv: IV,
    encrypted: Buffer.concat([cipher.update(data), cipher.final()]),
  };
}

//decrypt the data
function aesDecrypt(key, data, IV) {
  var validKey = Buffer.from(key);
  var cipher = crypto.createDecipheriv("aes-256-cbc", validKey, IV);
  return Buffer.concat([cipher.update(data), cipher.final()]);
}

//#region dafuq
//I don't know if i'm gonna replace these ones lol
function unsafeAESe(text, key) {
  var cipher = crypto.createCipher("aes-256-cbc", key);
  var crypted = cipher.update(text, "utf8", "hex");
  crypted += cipher.final("hex");
  return crypted;
}

function unsafeAESd(text, key) {
  var decipher = crypto.createDecipher("aes-256-cbc", key);
  var dec = decipher.update(text, "hex", "utf8");
  dec += decipher.final("utf8");
  return dec;
}

//#endregion
//console.log(this.getAllAccountFiles());
/*
this.encryptData({
  name: "Netflix 1",
  user: "nope",
  email: 'yo@yo.es',
  password: "yup this is da password yo",
});*/

//console.log(this.decryptData("e9bca4bb3d5dca1dd585a3c02c99af2e", passwordHash));
//console.log(privateKey);
//exports.generateKeyPair('si');
/*
var privateKey = exports.readPrivateKey();
var publicKey = exports.readPublicKey();

var encp = crypto.publicEncrypt(publicKey, Buffer.from("hola"));
var decp = crypto.privateDecrypt({ key: privateKey, passphrase: "si" }, encp);

console.log(encp.toString("hex"));
console.log(decp.toString("utf8"));*/

/*
const sign = crypto.createSign('SHA256');
sign.update('some data to sign');
sign.end();
const signature = sign.sign({key:privateKey , passphrase:'top secret'});

const verify = crypto.createVerify('SHA256');
verify.update('some data to sign');
verify.end();
console.log(verify.verify(publicKey, signature));

console.log(signature);
// Prints: true*/
