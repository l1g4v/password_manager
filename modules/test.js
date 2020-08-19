var crypto = require('crypto');
var buf = crypto.randomBytes(24);
console.log(buf.slice(0,12));
console.log(buf.slice(12,buf.length));