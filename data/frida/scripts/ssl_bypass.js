
Java.perform(function() {
    console.log("[*] SSL Pinning Bypass Script Loaded");
    
    var TrustManager = {
        verify: function() {
            console.log("[+] Certificate check bypassed");
        }
    };

    // Create a new TrustManager that trusts everything
    var TrustManagers = [TrustManager];
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    var init = SSLContext.init.overload(
        "[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom");
    
    init.implementation = function(keyManager, trustManager, secureRandom) {
        console.log("[*] Bypassing SSL Pinning...");
        init.call(this, keyManager, TrustManagers, secureRandom);
    };
});