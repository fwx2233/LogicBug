Java.perform(function(){
    var arrlist_cls=Java.use("java.util.ArrayList");
    var trusted_manage_cls=Java.use("com.android.org.conscrypt.TrustManagerImpl");
    trusted_manage_cls.checkTrustedRecursive.implementation=function (certs, host, clientAuth, untrustedChain,
        trustAnchorChain, used) {
        let log_cls=Java.use("android.util.Log");
        let throwable_cls=Java.use("java.lang.Throwable");
        let backtrace_str=log_cls.getStackTraceString(throwable_cls.$new());
        //console.log(backtrace_str);
        //console.log("[*] TrustManagerImpl.checkTrustedRecursive(), not throwing an exception.")
        return arrlist_cls.$new();
    };
    var pinner_cls = Java.use("okhttp3.CertificatePinner");
    pinner_cls.check.overload("java.lang.String", "java.util.List").implementation=function(a,b){
        //console.log("[*] OkHTTP 3.x CertificatePinner.check(), not throwing an exception.")
        return;
    }
    var x509manager_cls=Java.use("javax.net.ssl.X509TrustManager");
    var ssl_context_cls=Java.use("javax.net.ssl.SSLContext");

    var X509TrustManager = Java.registerClass({
        implements: [x509manager_cls],
        methods: {
          // tslint:disable-next-line:no-empty
          checkClientTrusted(chain, authType) { },
          // tslint:disable-next-line:no-empty
          checkServerTrusted(chain, authType) { },
          getAcceptedIssuers() {
            return [];
          },
        },
        name: "com.sensepost.test.TrustManager",
    });
    var TrustManagers = [X509TrustManager.$new()];
    var SSLContextInit=ssl_context_cls.init.overload("[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom");
    SSLContextInit.implementation=function(keyManager, trustManager, secureRandom){
        //console.log("[*]SSLContextInit overriding TrustManager with empty one");
        SSLContextInit.call(this, keyManager, TrustManagers, secureRandom);
    }
});
