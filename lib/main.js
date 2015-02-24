/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

let { Cc, Ci, Cu } = require("chrome");

let { Services } = Cu.import("resource://gre/modules/Services.jsm", {});
let { console } = Cu.import("resource://gre/modules/devtools/Console.jsm", {});

let gDebug = true;
let gPrefix = "superskua: ";
function log(x) {
  if (gDebug) {
    console.log(gPrefix + x);
  }
}

let gSuperfishPEM =
  "MIIC9TCCAl6gAwIBAgIJANL8E4epRNznMA0GCSqGSIb3DQEBBQUAMFsxGDAWBgNV" +
  "BAoTD1N1cGVyZmlzaCwgSW5jLjELMAkGA1UEBxMCU0YxCzAJBgNVBAgTAkNBMQsw" +
  "CQYDVQQGEwJVUzEYMBYGA1UEAxMPU3VwZXJmaXNoLCBJbmMuMB4XDTE0MDUxMjE2" +
  "MjUyNloXDTM0MDUwNzE2MjUyNlowWzEYMBYGA1UEChMPU3VwZXJmaXNoLCBJbmMu" +
  "MQswCQYDVQQHEwJTRjELMAkGA1UECBMCQ0ExCzAJBgNVBAYTAlVTMRgwFgYDVQQD" +
  "Ew9TdXBlcmZpc2gsIEluYy4wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAOjz" +
  "Shh2Xxk/sc9Y6X9DBwmVgDXFD/5xMSeBmRImIKXfj2r8QlU57gk4idngNsSsAYJb" +
  "1Tnm+Y8HiN/+7vahFM6pdEXY/fAXVyqC4XouEpNarIrXFWPRt5tVgA9YvBxJ7SBi" +
  "3bZMpTrrHD2g/3pxptMQeDOuS8Ic/ZJKocPnQaQtAgMBAAGjgcAwgb0wDAYDVR0T" +
  "BAUwAwEB/zAdBgNVHQ4EFgQU+5izU38URC7o7tUJml4OVoaoNYgwgY0GA1UdIwSB" +
  "hTCBgoAU+5izU38URC7o7tUJml4OVoaoNYihX6RdMFsxGDAWBgNVBAoTD1N1cGVy" +
  "ZmlzaCwgSW5jLjELMAkGA1UEBxMCU0YxCzAJBgNVBAgTAkNBMQswCQYDVQQGEwJV" +
  "UzEYMBYGA1UEAxMPU3VwZXJmaXNoLCBJbmMuggkA0vwTh6lE3OcwDQYJKoZIhvcN" +
  "AQEFBQADgYEApHyg7ApKx3DEcWjzOyLi3JyN0JL+c35yK1VEmxu0Qusfr76645Oj" +
  "1IsYwpTws6a9ZTRMzST4GQvFFQra81eLqYbPbMPuhC+FCxkUF5i0DNSWi+kczJXJ" +
  "TtCqSwGl9t9JEoFqvtW+znZ9TqyLiOMw7TGEUI+88VAqW0qmXnwPcfo=";

// We need to ensure the proxy is uninstalled or we DoS users
function shouldAttemptRemoval() {
  // Check we're on Windows
  var osString = Cc["@mozilla.org/xre/app-info;1"]
                    .getService(Ci.nsIXULRuntime).OS;
  if ('WINNT' !== osString) {
    log("Superfish hotfix is windows only");
    return false;
  }

  // Test for the superfish uninstall key; if present, it's still
  // installed
  let registry = Cc["@mozilla.org/windows-registry-key;1"]
                    .createInstance(Ci.nsIWindowsRegKey);
  registry.open(Ci.nsIWindowsRegKey.ROOT_KEY_LOCAL_MACHINE,
                "SOFTWARE\\CLASSES\\CLSID",
                Ci.nsIWindowsRegKey.ACCESS_READ);
  if (registry.hasChild("{02966FA9-C01A-47E7-A169-C83AEA1FB0BA}")) {
    return false;
  }
  return true;
}

function getAllCerts() {
  let certCache = Cc["@mozilla.org/security/nsscertcache;1"]
                    .getService(Ci.nsINSSCertCache);
  certCache.cacheAllCerts();
  return certCache.getX509CachedCerts();
}

function makeTemporaryCert(certPEM) {
  let certdb = Cc["@mozilla.org/security/x509certdb;1"]
                 .getService(Ci.nsIX509CertDB);
  return certdb.constructX509FromBase64(certPEM);
}

function removeRoot(rootPEM) {
  let allCerts = getAllCerts();
  let tempCert = makeTemporaryCert(rootPEM);

  let enumerator = allCerts.getEnumerator();
  let removedAnyCerts = false;
  while (enumerator.hasMoreElements()) {
    let cert = enumerator.getNext().QueryInterface(Ci.nsIX509Cert);
    if (cert.sha256SubjectPublicKeyInfoDigest ==
        tempCert.sha256SubjectPublicKeyInfoDigest) {
      // This is for versions before bug 643041 merged these interfaces.
      if ("nsIX509Cert2" in Ci) {
        cert.QueryInterface(Ci.nsIX509Cert2);
      }
      cert.markForPermDeletion();
      removedAnyCerts = true;
    }
  }

  if (removedAnyCerts) {
    // Clear any active sessions/tickets
    let sdr = Cc["@mozilla.org/security/sdr;1"]
                .getService(Ci.nsISecretDecoderRing);
    sdr.logoutAndTeardown();
  }
}

let gInitialized = false;

exports.main = function(options, callbacks) {
  if (!gInitialized &&
      (options.loadReason == "startup" ||
       options.loadReason == "install" ||
       options.loadReason == "enable")) {
    log("initializing");
    try {
      if (shouldAttemptRemoval()) {
        log("Superfish is not installed; attempting to remove root");
        removeRoot(gSuperfishPEM);
      } else {
        log("not removing root");
      }
    } catch (error) {
      log("removing Superfish root failed: " + error);
    }
    gInitialized = true;
  }
};
