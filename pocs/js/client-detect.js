// Client detection for Arattai Mini-App PoC
// Detects Android WebView, iOS WKWebView, Electron, or plain browser.

(function(global) {
    "use strict";

    var ua = navigator.userAgent || "";

    function detect() {
        // Electron exposes process.versions.electron via contextBridge / window check
        var isElectron = (typeof window !== "undefined" && window.process &&
                          window.process.versions && window.process.versions.electron) ||
                         ua.indexOf("Electron") >= 0;

        // Arattai Android appends a custom UA suffix (MyApplication.getUserAgent())
        // e.g. "... ArattaiAndroid/<version>" — adjust pattern if needed
        var isAndroid = /Android/.test(ua) && /wv/.test(ua);  // WebView flag
        var isArattaiAndroid = isAndroid && (/Arattai/.test(ua) || /arattai/.test(ua));

        // iOS WKWebView: no "CriOS" or "FxiOS", contains "iPhone|iPad|iPod" + "AppleWebKit"
        var isIOS = /iPhone|iPad|iPod/.test(ua) && /AppleWebKit/.test(ua) && !isElectron;
        // WKWebView specifically (vs Safari): no "Safari" in UA, or has "Mobile/..."
        var isWKWebView = isIOS && !/Safari\//.test(ua);

        if (isElectron) return { id: "electron",  label: "Arattai Desktop (Electron)", badge: "desktop" };
        if (isArattaiAndroid) return { id: "android-arattai", label: "Arattai Android", badge: "android" };
        if (isAndroid)        return { id: "android-generic",  label: "Android WebView", badge: "android" };
        if (isWKWebView)      return { id: "ios-wkwebview",    label: "Arattai iOS (WKWebView)", badge: "ios" };
        if (isIOS)            return { id: "ios-safari",       label: "iOS Safari", badge: "ios" };
        return { id: "browser", label: "Desktop Browser (Web Client)", badge: "web" };
    }

    global.ArattaiClientDetect = detect();

})(window);
