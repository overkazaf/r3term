
Java.perform(function() {
    console.log("[*] AES Hook Loaded");
    
    var cipher = Java.use("javax.crypto.Cipher");
    cipher.doFinal.overload("[B").implementation = function(buffer) {
        console.log("[+] Cipher.doFinal([B]) called");
        console.log("[*] Algorithm: " + this.getAlgorithm());
        console.log("[*] Input: " + buffer);
        var ret = this.doFinal.call(this, buffer);
        console.log("[*] Output: " + ret);
        return ret;
    };
});