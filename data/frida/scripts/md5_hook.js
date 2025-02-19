
Java.perform(function() {
    console.log("[*] MD5 Hook Loaded");
    
    // Hook MessageDigest
    var MessageDigest = Java.use("java.security.MessageDigest");
    MessageDigest.getInstance.overload("java.lang.String").implementation = function(algorithm) {
        console.log("[+] MessageDigest.getInstance(" + algorithm + ") called");
        return this.getInstance.call(this, algorithm);
    };
    
    MessageDigest.digest.overload().implementation = function() {
        var ret = this.digest.call(this);
        console.log("[+] MessageDigest.digest() called");
        console.log("[*] Input: " + this.toString());
        console.log("[*] Output: " + ret);
        return ret;
    };
});