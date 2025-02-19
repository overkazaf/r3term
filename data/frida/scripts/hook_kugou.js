Java.perform(function() {
    const TAG = "[KuGouHook] ";

    function log(message) {
        console.log(TAG + message);
    }

    // 辅助函数：将字节数组转为hex字符串
    function bytes2hex(array) {
        let result = '';
        for(let i = 0; i < array.length; ++i) {
            result += ('0' + (array[i] & 0xFF).toString(16)).slice(-2);
        }
        return result;
    }

    // // Hook Map操作
    const mapClasses = [
        'java.util.HashMap',
        'java.util.LinkedHashMap',
        'java.util.concurrent.ConcurrentHashMap',
        'java.util.TreeMap'
    ];

    mapClasses.forEach(className => {
        try {
            const mapClass = Java.use(className);
            let tokenHookCount = 0;
            let userIdHookCount = 0;
            // Hook put方法
            mapClass.put.implementation = function(key, value) {
                if (key.toString().toLowerCase() == "token" || key.toString().toLowerCase() == "userid") {
                    log("Kugou put: " + key + " = " + value);
                    if (key.toString().toLowerCase() == "token" && tokenHookCount < 2) {
                        log("Kugou token: " + value);
                        tokenHookCount++;
                    }
                    if (key.toString().toLowerCase() == "userid" && userIdHookCount < 2) {
                        log("Kugou userid: " + value);
                        userIdHookCount++;
                    }
                }
                return this.put(key, value);
            };

            // Hook putAll方法
            mapClass.putAll.implementation = function(map) {
                return this.putAll(map);
            };

        } catch(e) {
            // log(`${className} not found`);
        }
    });

    // // Hook MessageDigest
    // const MessageDigest = Java.use('java.security.MessageDigest');
    
    // // Hook getInstance
    // MessageDigest.getInstance.overload('java.lang.String').implementation = function(algorithm) {
    //     const result = this.getInstance(algorithm);
    //     if (algorithm.toLowerCase() === "md5") {
    //         log("[MD5] MessageDigest.getInstance called");
    //         // 打印调用栈
    //         log("Stack:\n" + Thread.backtrace(this.context, Backtracer.ACCURATE)
    //             .map(DebugSymbol.fromAddress).join("\n"));
    //     }
    //     return result;
    // };

    // // Hook update方法
    // MessageDigest.update.overload('[B').implementation = function(input) {
    //     if (this.getAlgorithm() === "MD5") {
    //         log("[MD5] Update with bytes: " + bytes2hex(input));
    //         // 尝试转换为字符串
    //         try {
    //             const inputString = Java.use('java.lang.String').$new(input);
    //             log("[MD5] Input as string: " + inputString);
    //         } catch(e) {}
    //     }
    //     return this.update(input);
    // };

    // // Hook digest方法
    // MessageDigest.digest.overload().implementation = function() {
    //     const result = this.digest();
    //     if (this.getAlgorithm() === "MD5") {
    //         log("[MD5] Digest result: " + bytes2hex(result));
    //     }
    //     return result;
    // };

    // // Hook 常见的第三方MD5工具类
    // try {
    //     // Apache Commons Codec
    //     const DigestUtils = Java.use('org.apache.commons.codec.digest.DigestUtils');
    //     DigestUtils.md5Hex.overload('java.lang.String').implementation = function(input) {
    //         log("[MD5] DigestUtils.md5Hex input: " + input);
    //         const result = this.md5Hex(input);
    //         log("[MD5] DigestUtils.md5Hex result: " + result);
    //         return result;
    //     };
    // } catch(e) {
    //     log("DigestUtils not found");
    // }

    // // Hook native层MD5函数
    // try {
    //     const md5Functions = [
    //         "MD5_Init",
    //         "MD5_Update",
    //         "MD5_Final",
    //         "MD5Transform",
    //         "CC_MD5",
    //         "CC_MD5_Init",
    //         "CC_MD5_Update",
    //         "CC_MD5_Final"
    //     ];

    //     md5Functions.forEach(funcName => {
    //         const func = Module.findExportByName(null, funcName);
    //         if (func) {
    //             Interceptor.attach(func, {
    //                 onEnter: function(args) {
    //                     log("[Native MD5] " + funcName + " called");
    //                     if (funcName.includes("Update")) {
    //                         const buf = args[1];
    //                         const len = args[2].toInt32();
    //                         const data = Memory.readByteArray(buf, len);
    //                         log("[Native MD5] Input data: " + bytes2hex(new Uint8Array(data)));
    //                         // 尝试转换为字符串
    //                         try {
    //                             const str = buf.readUtf8String(len);
    //                             log("[Native MD5] Input as string: " + str);
    //                         } catch(e) {}
    //                     }
    //                 },
    //                 onLeave: function(retval) {
    //                     if (funcName.includes("Final")) {
    //                         log("[Native MD5] Calculation completed");
    //                         try {
    //                             const resultBuf = Memory.readByteArray(retval, 16);
    //                             log("[Native MD5] Result: " + bytes2hex(new Uint8Array(resultBuf)));
    //                         } catch(e) {}
    //                     }
    //                 }
    //             });
    //         }
    //     });
    // } catch(e) {
    //     log("Error hooking native MD5 functions: " + e);
    // }

    log("Kugou Hook Initialized with MD5 monitoring");
}); 