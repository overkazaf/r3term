
Java.perform(function() {
    console.log("[*] Root Detection Bypass Loaded");
    
    var RootPackages = ["com.noshufou.android.su", "com.thirdparty.superuser", "eu.chainfire.supersu",
                        "com.topjohnwu.magisk"];
    
    var RootBinary = ["su", "busybox"];
    var RootProperties = ["ro.build.selinux"];
    
    var Build = Java.use("android.os.Build");
    var File = Java.use("java.io.File");
    var String = Java.use("java.lang.String");
    
    // Bypass file-based checks
    File.exists.implementation = function() {
        var name = this.getAbsolutePath();
        for (var i = 0; i < RootBinary.length; i++) {
            if (name.indexOf(RootBinary[i]) > -1) {
                console.log("[+] Bypassing root check for: " + name);
                return false;
            }
        }
        return this.exists.call(this);
    };
});