//! The plain-language report shown first to non-experts: one verdict
//! (traffic light) with reasons, who made the file, what it may access
//! (phone-style permissions), who it talks to, which third-party kits are
//! built in (analytics, ads, crash reporting…), and simple grades.
//!
//! Everything here is derived from Drishti's static results plus the
//! results of tools/lookups the person chose to run. It's a summary, so
//! each item links back to its evidence (behaviour, entitlement, string,
//! tool result).

use crate::bundle::{Bundle, Codesign, usage_label};
use crate::state::Session;
use drishti_model::Format;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashSet};

// ---------------------------------------------------------------- SDKs

struct Sdk {
    name: &'static str,
    /// "analytics" | "ads" | "crash" | "attribution" | "messaging" | "updates" | "payments" | "login" | "support" | "framework"
    cat: &'static str,
    /// Class / symbol / string prefixes (case-sensitive).
    prefixes: &'static [&'static str],
    /// Substrings of linked library or bundled framework names (case-insensitive).
    libs: &'static [&'static str],
    /// Host suffixes of URLs found in the file.
    hosts: &'static [&'static str],
    /// Substrings of paths inside archives (APK/IPA/JAR/asar).
    files: &'static [&'static str],
}

const SDKS: &[Sdk] = &[
    Sdk {
        name: "Google Analytics for Firebase",
        cat: "analytics",
        prefixes: &["FIRAnalytics", "FIRApp", "APMAnalytics"],
        libs: &["FirebaseAnalytics", "GoogleAppMeasurement"],
        hosts: &[
            "app-measurement.com",
            "firebase-settings.crashlytics.com",
            "firebaseinstallations.googleapis.com",
        ],
        files: &[
            "firebase-analytics",
            "com/google/firebase/analytics",
            "google-services",
        ],
    },
    Sdk {
        name: "Google Analytics",
        cat: "analytics",
        prefixes: &["GAITracker", "GAI"],
        libs: &["GoogleAnalytics"],
        hosts: &[
            "google-analytics.com",
            "analytics.google.com",
            "googletagmanager.com",
        ],
        files: &["com/google/android/gms/analytics"],
    },
    Sdk {
        name: "Firebase Crashlytics",
        cat: "crash",
        prefixes: &["FIRCrashlytics", "FIRCLS", "Crashlytics"],
        libs: &["FirebaseCrashlytics", "Crashlytics"],
        hosts: &["crashlytics.com"],
        files: &["firebase-crashlytics", "crashlytics"],
    },
    Sdk {
        name: "Sentry",
        cat: "crash",
        prefixes: &["SentrySDK", "SentryClient", "SentryCrash", "Sentry.SDK"],
        libs: &["Sentry", "sentry"],
        hosts: &["sentry.io", "ingest.sentry.io"],
        files: &["io/sentry", "@sentry/"],
    },
    Sdk {
        name: "Bugsnag",
        cat: "crash",
        prefixes: &["Bugsnag"],
        libs: &["Bugsnag"],
        hosts: &["bugsnag.com"],
        files: &["com/bugsnag", "@bugsnag/"],
    },
    Sdk {
        name: "Microsoft App Center",
        cat: "crash",
        prefixes: &["MSACAppCenter", "MSAppCenter"],
        libs: &["AppCenter"],
        hosts: &["appcenter.ms", "in.appcenter.ms"],
        files: &["com/microsoft/appcenter"],
    },
    Sdk {
        name: "Datadog",
        cat: "analytics",
        prefixes: &["DDDatadog", "DatadogCore"],
        libs: &["Datadog"],
        hosts: &["datadoghq.com", "browser-intake-datadoghq.com"],
        files: &["com/datadog", "@datadog/"],
    },
    Sdk {
        name: "New Relic",
        cat: "analytics",
        prefixes: &["NewRelic", "NRMA"],
        libs: &["NewRelic"],
        hosts: &["newrelic.com", "nr-data.net"],
        files: &["com/newrelic"],
    },
    Sdk {
        name: "Facebook (Meta) SDK",
        cat: "analytics",
        prefixes: &["FBSDK", "FBAEMKit", "FBSDKCoreKit"],
        libs: &["FBSDK", "FBAEMKit", "FacebookCore"],
        hosts: &[
            "graph.facebook.com",
            "connect.facebook.net",
            "facebook.com/tr",
        ],
        files: &["com/facebook/appevents", "com/facebook/FacebookSdk"],
    },
    Sdk {
        name: "Meta Audience Network (ads)",
        cat: "ads",
        prefixes: &["FBAdView", "FBInterstitialAd", "FBAudienceNetwork"],
        libs: &["FBAudienceNetwork"],
        hosts: &["an.facebook.com"],
        files: &["com/facebook/ads"],
    },
    Sdk {
        name: "Google Mobile Ads (AdMob)",
        cat: "ads",
        prefixes: &[
            "GADMobileAds",
            "GADBannerView",
            "GADInterstitial",
            "GADRequest",
        ],
        libs: &["GoogleMobileAds"],
        hosts: &[
            "googleads.g.doubleclick.net",
            "pagead2.googlesyndication.com",
            "admob.com",
        ],
        files: &["com/google/android/gms/ads", "play-services-ads"],
    },
    Sdk {
        name: "AppLovin",
        cat: "ads",
        prefixes: &["ALSdk", "MAAdView", "ALAdService"],
        libs: &["AppLovinSDK"],
        hosts: &["applovin.com", "applvn.com"],
        files: &["com/applovin"],
    },
    Sdk {
        name: "Unity Ads",
        cat: "ads",
        prefixes: &["UnityAds"],
        libs: &["UnityAds"],
        hosts: &["unityads.unity3d.com", "ads.unity3d.com"],
        files: &["com/unity3d/ads", "com/unity3d/services"],
    },
    Sdk {
        name: "ironSource",
        cat: "ads",
        prefixes: &["IronSourceAds", "ISAdapterBaseProtocol"],
        libs: &["IronSource"],
        hosts: &["ironsrc.com", "supersonicads.com"],
        files: &["com/ironsource"],
    },
    Sdk {
        name: "Vungle / Liftoff",
        cat: "ads",
        prefixes: &["VungleSDK", "VungleAds"],
        libs: &["VungleAds", "VungleSDK"],
        hosts: &["vungle.com"],
        files: &["com/vungle"],
    },
    Sdk {
        name: "Chartboost",
        cat: "ads",
        prefixes: &["Chartboost"],
        libs: &["Chartboost"],
        hosts: &["chartboost.com"],
        files: &["com/chartboost"],
    },
    Sdk {
        name: "InMobi",
        cat: "ads",
        prefixes: &["IMSdk", "IMBanner"],
        libs: &["InMobiSDK"],
        hosts: &["inmobi.com"],
        files: &["com/inmobi"],
    },
    Sdk {
        name: "Mintegral",
        cat: "ads",
        prefixes: &["MTGSDK"],
        libs: &["MTGSDK"],
        hosts: &["mintegral.com", "rayjump.com"],
        files: &["com/mbridge", "com/mintegral"],
    },
    Sdk {
        name: "Pangle (ByteDance)",
        cat: "ads",
        prefixes: &["BUAdSDK", "PAGSdk"],
        libs: &["BUAdSDK", "PAGAdSDK"],
        hosts: &["pangle.io", "pangleglobal.com", "byteoversea.com"],
        files: &["com/bytedance/sdk/openadsdk"],
    },
    Sdk {
        name: "AppsFlyer",
        cat: "attribution",
        prefixes: &["AppsFlyerLib", "AppsFlyer"],
        libs: &["AppsFlyerLib"],
        hosts: &["appsflyer.com", "appsflyersdk.com"],
        files: &["com/appsflyer"],
    },
    Sdk {
        name: "Adjust",
        cat: "attribution",
        prefixes: &["ADJAdjust", "AdjustSdk"],
        libs: &["AdjustSdk"],
        hosts: &["adjust.com", "adjust.io"],
        files: &["com/adjust/sdk"],
    },
    Sdk {
        name: "Branch",
        cat: "attribution",
        prefixes: &["BranchSDK", "BNCServerInterface"],
        libs: &["Branch"],
        hosts: &["branch.io", "app.link"],
        files: &["io/branch"],
    },
    Sdk {
        name: "Kochava",
        cat: "attribution",
        prefixes: &["KochavaTracker"],
        libs: &["KochavaTracker"],
        hosts: &["kochava.com"],
        files: &["com/kochava"],
    },
    Sdk {
        name: "Amplitude",
        cat: "analytics",
        prefixes: &["AMPAmplitude", "AmplitudeSwift"],
        libs: &["Amplitude"],
        hosts: &["amplitude.com", "api2.amplitude.com"],
        files: &["com/amplitude", "@amplitude/"],
    },
    Sdk {
        name: "Mixpanel",
        cat: "analytics",
        prefixes: &["MixpanelInstance", "Mixpanel.Mixpanel"],
        libs: &["Mixpanel"],
        hosts: &["mixpanel.com"],
        files: &["com/mixpanel", "mixpanel-browser"],
    },
    Sdk {
        name: "Segment",
        cat: "analytics",
        prefixes: &["SEGAnalytics", "SegmentAnalytics"],
        libs: &["Analytics-Segment", "Segment"],
        hosts: &["segment.io", "segment.com", "api.segment.io"],
        files: &["com/segment/analytics", "@segment/"],
    },
    Sdk {
        name: "PostHog",
        cat: "analytics",
        prefixes: &["PostHogSDK", "PHGPostHog"],
        libs: &["PostHog"],
        hosts: &["posthog.com", "i.posthog.com"],
        files: &["com/posthog", "posthog-js"],
    },
    Sdk {
        name: "Heap",
        cat: "analytics",
        prefixes: &["HeapIOS", "HeapAnalytics"],
        libs: &["Heap"],
        hosts: &["heapanalytics.com", "heap.io"],
        files: &["com/heapanalytics"],
    },
    Sdk {
        name: "Flurry",
        cat: "analytics",
        prefixes: &["FlurryAnalytics", "FlurrySDK"],
        libs: &["Flurry"],
        hosts: &["flurry.com"],
        files: &["com/flurry"],
    },
    Sdk {
        name: "Yandex AppMetrica",
        cat: "analytics",
        prefixes: &["YMMYandexMetrica", "AppMetrica"],
        libs: &["YandexMobileMetrica", "AppMetrica"],
        hosts: &["appmetrica.yandex.net", "mc.yandex.ru"],
        files: &["io/appmetrica", "com/yandex/metrica"],
    },
    Sdk {
        name: "Countly",
        cat: "analytics",
        prefixes: &["CountlyConfig"],
        libs: &["Countly"],
        hosts: &["count.ly"],
        files: &["ly/count/android"],
    },
    Sdk {
        name: "Statsig",
        cat: "analytics",
        prefixes: &["StatsigClient"],
        libs: &["Statsig"],
        hosts: &["statsig.com", "statsigapi.net"],
        files: &["com/statsig", "statsig-js"],
    },
    Sdk {
        name: "LaunchDarkly",
        cat: "analytics",
        prefixes: &["LDClient", "LaunchDarkly"],
        libs: &["LaunchDarkly"],
        hosts: &["launchdarkly.com"],
        files: &["com/launchdarkly"],
    },
    Sdk {
        name: "FullStory (session recording)",
        cat: "analytics",
        prefixes: &["FullStoryAPI", "FullStory.FS"],
        libs: &["FullStory"],
        hosts: &["fullstory.com"],
        files: &["com/fullstory"],
    },
    Sdk {
        name: "Smartlook (session recording)",
        cat: "analytics",
        prefixes: &["SmartlookAnalytics"],
        libs: &["Smartlook"],
        hosts: &["smartlook.com", "smartlook.cloud"],
        files: &["com/smartlook"],
    },
    Sdk {
        name: "Hotjar (session recording)",
        cat: "analytics",
        prefixes: &["HotjarSDK"],
        libs: &[],
        hosts: &["hotjar.com", "hotjar.io"],
        files: &["com/hotjar"],
    },
    Sdk {
        name: "Braze",
        cat: "messaging",
        prefixes: &["Appboy", "BRZBraze", "BrazeKit"],
        libs: &["Appboy", "BrazeKit"],
        hosts: &["braze.com", "appboy.com"],
        files: &["com/braze", "com/appboy"],
    },
    Sdk {
        name: "OneSignal",
        cat: "messaging",
        prefixes: &["OneSignalFramework", "OSNotification"],
        libs: &["OneSignal"],
        hosts: &["onesignal.com"],
        files: &["com/onesignal"],
    },
    Sdk {
        name: "Firebase Cloud Messaging",
        cat: "messaging",
        prefixes: &["FIRMessaging"],
        libs: &["FirebaseMessaging"],
        hosts: &["fcm.googleapis.com", "fcmregistrations.googleapis.com"],
        files: &["firebase-messaging", "com/google/firebase/messaging"],
    },
    Sdk {
        name: "Intercom",
        cat: "support",
        prefixes: &["ICMIntercom", "IntercomSDK"],
        libs: &["Intercom"],
        hosts: &["intercom.io", "intercomcdn.com"],
        files: &["io/intercom"],
    },
    Sdk {
        name: "Zendesk",
        cat: "support",
        prefixes: &["ZDKSupport", "ZendeskSDK"],
        libs: &["Zendesk"],
        hosts: &["zendesk.com", "zdassets.com"],
        files: &["zendesk"],
    },
    Sdk {
        name: "Sparkle (auto-updates)",
        cat: "updates",
        prefixes: &["SUUpdater", "SPUUpdater", "SPUStandardUpdaterController"],
        libs: &["Sparkle"],
        hosts: &[],
        files: &[],
    },
    Sdk {
        name: "Squirrel (auto-updates)",
        cat: "updates",
        prefixes: &["SQRLUpdater"],
        libs: &["Squirrel"],
        hosts: &[],
        files: &[],
    },
    Sdk {
        name: "Electron",
        cat: "framework",
        prefixes: &[],
        libs: &["Electron Framework"],
        hosts: &[],
        files: &[],
    },
    Sdk {
        name: "Stripe",
        cat: "payments",
        prefixes: &["STPAPIClient", "STPPayment", "StripeCore"],
        libs: &["Stripe"],
        hosts: &["api.stripe.com", "js.stripe.com"],
        files: &["com/stripe/android", "@stripe/"],
    },
    Sdk {
        name: "RevenueCat",
        cat: "payments",
        prefixes: &["RCPurchases", "RevenueCat"],
        libs: &["RevenueCat"],
        hosts: &["revenuecat.com"],
        files: &["com/revenuecat"],
    },
    Sdk {
        name: "Paddle",
        cat: "payments",
        prefixes: &["PaddleSDK", "PADProduct"],
        libs: &["Paddle"],
        hosts: &["paddle.com", "paddle.net"],
        files: &[],
    },
    Sdk {
        name: "Google Sign-In",
        cat: "login",
        prefixes: &["GIDSignIn", "GIDConfiguration"],
        libs: &["GoogleSignIn"],
        hosts: &["accounts.google.com"],
        files: &["com/google/android/gms/auth"],
    },
    Sdk {
        name: "Auth0",
        cat: "login",
        prefixes: &["A0Auth", "Auth0Swift"],
        libs: &["Auth0"],
        hosts: &["auth0.com"],
        files: &["com/auth0"],
    },
];

pub fn cat_label(c: &str) -> &'static str {
    match c {
        "analytics" => "Usage analytics (tracks how you use the app)",
        "ads" => "Advertising",
        "crash" => "Crash reporting",
        "attribution" => "Marketing attribution (which ad brought you here)",
        "messaging" => "Push notifications / marketing messages",
        "updates" => "Automatic updates",
        "payments" => "Payments",
        "login" => "Sign-in",
        "support" => "Customer support chat",
        "framework" => "App framework",
        _ => "Other",
    }
}

fn host_of(url: &str) -> Option<String> {
    let rest = url.split_once("://").map(|x| x.1).unwrap_or(url);
    let host = rest.split(['/', '?', '#']).next()?;
    let host = host
        .rsplit('@')
        .next()?
        .split(':')
        .next()?
        .trim_end_matches('.')
        .to_lowercase();
    (host.contains('.')
        && host.len() <= 253
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-'))
    .then_some(host)
}

fn host_matches(host: &str, suffix: &str) -> bool {
    let suffix = suffix.split('/').next().unwrap_or(suffix);
    host == suffix || host.ends_with(&format!(".{suffix}"))
}

/// Third-party kits found in the file (and its app bundle).
pub fn sdks(s: &Session, bundle: Option<&Bundle>, hosts: &[String]) -> Vec<Value> {
    let mut libs: Vec<String> = s.info.libraries.iter().map(|l| l.to_lowercase()).collect();
    if let Some(img) = &s.image {
        libs.extend(img.libraries.iter().map(|l| l.to_lowercase()));
    }
    if let Some(b) = bundle {
        libs.extend(b.frameworks.iter().map(|f| f.to_lowercase()));
    }
    let children: Vec<&str> = s.info.children.iter().map(|c| c.path.as_str()).collect();
    let mut out = Vec::new();
    for k in SDKS {
        let mut evidence: Vec<String> = Vec::new();
        if let Some(l) = k.libs.iter().find(|n| {
            let n = n.to_lowercase();
            libs.iter().any(|l| {
                l.rsplit('/').any(|seg| {
                    seg == format!("{n}.framework")
                        || seg == n
                        || seg == format!("lib{n}.dylib")
                        || seg.starts_with(&format!("{n}."))
                })
            })
        }) {
            evidence.push(format!("bundles the {l} library"));
        }
        if let Some(h) = hosts
            .iter()
            .find(|h| k.hosts.iter().any(|x| host_matches(h, x)))
        {
            evidence.push(format!("contains the address {h}"));
        }
        if let Some(f) = k
            .files
            .iter()
            .find(|f| children.iter().any(|c| c.contains(*f)))
        {
            evidence.push(format!("contains files named like {f}"));
        }
        if evidence.is_empty() && !k.prefixes.is_empty() {
            // Class names: exact name or name + separator, so "Heap" doesn't match "HeapSort".
            if let Some(hit) = s.strings.iter().take(400_000).find_map(|st| {
                let v = st.value.as_str();
                k.prefixes.iter().find(|p| {
                    v.starts_with(**p)
                        && p.len() >= 5
                        && v.len() <= 80
                        // Word boundary: "SentrySDK" matches, "SentrySDKish" doesn't.
                        && v[p.len()..].chars().next().is_none_or(|c| !c.is_ascii_lowercase())
                        && v.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == ':')
                })
            }) {
                evidence.push(format!("contains code named {hit}…"));
            }
        }
        if !evidence.is_empty() {
            out.push(json!({"name": k.name, "category": k.cat, "category_label": cat_label(k.cat), "evidence": evidence}));
        }
    }
    out
}

// ---------------------------------------------------------------- network

/// Domains that appear as text but are not contacted (XML namespaces,
/// licences, documentation).
const NOT_CONTACTED: &[&str] = &[
    "w3.org",
    "xmlsoap.org",
    "purl.org",
    "openxmlformats.org",
    "schemas.microsoft.com",
    "ns.adobe.com",
    "apple.com/dtds",
    "www.apache.org",
    "opensource.org",
    "gnu.org",
    "creativecommons.org",
    "unicode.org",
    "ietf.org",
    "json-schema.org",
    "mozilla.org/mpl",
    "spdx.org",
    "example.com",
    "example.org",
    "example.net",
    "localhost",
    "xml.org",
    "oasis-open.org",
    "schema.org",
    "openssl.org",
    "zlib.net",
    "sqlite.org",
    "github.com",
    "chromium.org",
    "developer.apple.com",
    "llvm.org",
    "swift.org",
    "microsoft.com/pkiops",
    "digicert.com",
    "verisign.com",
    "symantec.com",
    "globalsign.com",
    "sectigo.com",
    "usertrust.com",
    "entrust.net",
    "letsencrypt.org",
    "crl.",
    "ocsp.",
    "certificates.",
];

fn host_category(h: &str, own: &[String]) -> (&'static str, &'static str) {
    let any = |list: &[&str]| list.iter().any(|x| host_matches(h, x));
    // "brand:<name>" entries match the second-level label (core.telegram.org).
    let sld = h.rsplit('.').nth(1).unwrap_or("");
    if own.iter().any(|o| match o.strip_prefix("brand:") {
        Some(b) => sld == b,
        None => host_matches(h, o),
    }) {
        return ("own", "The maker's own websites");
    }
    if NOT_CONTACTED.iter().any(|x| {
        h.contains(x.split('/').next().unwrap_or(x)) && (x.contains('.') || h.starts_with(x))
    }) {
        return (
            "text",
            "Mentioned only (standards, licences, certificates; usually not contacted)",
        );
    }
    for k in SDKS {
        if any(k.hosts) {
            return match k.cat {
                "ads" => ("ads", "Advertising"),
                "analytics" | "attribution" => ("tracking", "Analytics and tracking"),
                "crash" => ("crash", "Crash reporting"),
                _ => ("services", "Third-party services"),
            };
        }
    }
    if any(&[
        "apple.com",
        "icloud.com",
        "mzstatic.com",
        "apple-cloudkit.com",
        "itunes.apple.com",
    ]) {
        return ("platform", "Apple services");
    }
    if any(&[
        "googleapis.com",
        "gstatic.com",
        "google.com",
        "googleusercontent.com",
        "youtube.com",
        "gvt1.com",
        "goo.gl",
    ]) {
        return ("platform", "Google services");
    }
    if any(&[
        "microsoft.com",
        "live.com",
        "office.com",
        "windows.net",
        "azure.com",
        "msftauth.net",
        "bing.com",
        "msn.com",
    ]) {
        return ("platform", "Microsoft services");
    }
    if any(&[
        "amazonaws.com",
        "cloudfront.net",
        "cloudflare.com",
        "akamaized.net",
        "akamai.net",
        "fastly.net",
        "jsdelivr.net",
        "unpkg.com",
        "cdnjs.cloudflare.com",
    ]) {
        return ("cdn", "Cloud hosting and content delivery");
    }
    ("other", "Other websites mentioned")
}

/// The maker's own domains: from the bundle id / signing identifier
/// (`org.telegram.desktop` → telegram.org).
fn own_domains(bundle: Option<&Bundle>, ident: Option<&str>) -> Vec<String> {
    let mut v = Vec::new();
    for id in [bundle.and_then(|b| b.bundle_id.as_deref()), ident]
        .into_iter()
        .flatten()
    {
        let parts: Vec<&str> = id.split('.').collect();
        if parts.len() >= 2
            && matches!(
                parts[0],
                "com"
                    | "org"
                    | "net"
                    | "io"
                    | "app"
                    | "co"
                    | "dev"
                    | "me"
                    | "ru"
                    | "de"
                    | "uk"
                    | "in"
            )
        {
            v.push(format!("{}.{}", parts[1].to_lowercase(), parts[0]));
            if !matches!(parts[1], "google" | "apple" | "microsoft") {
                // Brand used with other TLDs (telegram.org vs t.me is not guessable).
                for tld in ["com", "org", "net", "io", "app"] {
                    v.push(format!("{}.{tld}", parts[1].to_lowercase()));
                }
            }
        }
    }
    // The app's brand: last part of the bundle id (ru.keepcoder.Telegram → telegram).
    for id in [bundle.and_then(|b| b.bundle_id.as_deref()), ident]
        .into_iter()
        .flatten()
    {
        let parts: Vec<&str> = id.split('.').collect();
        for p in parts.iter().skip(1) {
            let b = p.to_lowercase();
            if b.len() >= 4
                && b.chars().all(|c| c.is_ascii_alphanumeric())
                && !matches!(
                    b.as_str(),
                    "google"
                        | "apple"
                        | "microsoft"
                        | "desktop"
                        | "macos"
                        | "client"
                        | "app"
                        | "mac"
                )
            {
                v.push(format!("brand:{b}"));
            }
        }
    }
    v.sort();
    v.dedup();
    v
}

pub fn network(
    hosts: &[String],
    ips: &[String],
    bundle: Option<&Bundle>,
    ident: Option<&str>,
) -> Value {
    let own = own_domains(bundle, ident);
    let mut groups: BTreeMap<&str, (&str, Vec<String>)> = BTreeMap::new();
    for h in hosts {
        let (k, label) = host_category(h, &own);
        groups
            .entry(k)
            .or_insert((label, Vec::new()))
            .1
            .push(h.clone());
    }
    let order = [
        "own", "tracking", "ads", "crash", "services", "platform", "cdn", "other", "text",
    ];
    let mut out: Vec<Value> = Vec::new();
    for k in order {
        if let Some((label, hs)) = groups.get(k) {
            out.push(json!({"id": k, "label": label, "hosts": hs}));
        }
    }
    let contacted: usize = out
        .iter()
        .filter(|g| g["id"] != "text")
        .map(|g| g["hosts"].as_array().map_or(0, |a| a.len()))
        .sum();
    json!({"groups": out, "ips": ips, "contacted": contacted})
}

pub fn hosts_and_ips(iocs: &Value) -> (Vec<String>, Vec<String>) {
    let mut hosts = HashSet::new();
    let mut ips = HashSet::new();
    for i in iocs.as_array().into_iter().flatten() {
        let v = i["value"].as_str().unwrap_or("");
        match i["kind"].as_str() {
            Some("url") => {
                if let Some(h) = host_of(v) {
                    if h.parse::<std::net::Ipv4Addr>().is_ok() {
                        ips.insert(h);
                    } else {
                        hosts.insert(h);
                    }
                }
            }
            Some("ip") => {
                if let Some(ip) = v
                    .split(':')
                    .next()
                    .filter(|x| x.parse::<std::net::Ipv4Addr>().is_ok())
                {
                    ips.insert(ip.to_string());
                }
            }
            _ => {}
        }
    }
    let mut h: Vec<String> = hosts.into_iter().collect();
    h.sort();
    h.truncate(400);
    let mut i: Vec<String> = ips.into_iter().collect();
    i.sort();
    i.truncate(100);
    (h, i)
}

// ---------------------------------------------------------------- permissions

struct Perm {
    id: &'static str,
    label: &'static str,
    icon: &'static str,
    sensitive: bool,
}

const PERMS: &[Perm] = &[
    Perm {
        id: "camera",
        label: "Camera",
        icon: "camera",
        sensitive: true,
    },
    Perm {
        id: "microphone",
        label: "Microphone",
        icon: "mic",
        sensitive: true,
    },
    Perm {
        id: "screen",
        label: "See or record your screen",
        icon: "screen",
        sensitive: true,
    },
    Perm {
        id: "keyboard",
        label: "Watch what you type",
        icon: "keyboard",
        sensitive: true,
    },
    Perm {
        id: "location",
        label: "Location",
        icon: "location",
        sensitive: true,
    },
    Perm {
        id: "contacts",
        label: "Contacts",
        icon: "contacts",
        sensitive: true,
    },
    Perm {
        id: "photos",
        label: "Photos",
        icon: "photos",
        sensitive: true,
    },
    Perm {
        id: "calendar",
        label: "Calendar",
        icon: "calendar",
        sensitive: false,
    },
    Perm {
        id: "reminders",
        label: "Reminders",
        icon: "calendar",
        sensitive: false,
    },
    Perm {
        id: "clipboard",
        label: "Read the clipboard",
        icon: "clipboard",
        sensitive: false,
    },
    Perm {
        id: "files",
        label: "Your files and folders",
        icon: "folder",
        sensitive: false,
    },
    Perm {
        id: "passwords",
        label: "Saved passwords (Keychain)",
        icon: "key",
        sensitive: true,
    },
    Perm {
        id: "automation",
        label: "Control other apps",
        icon: "automation",
        sensitive: true,
    },
    Perm {
        id: "startup",
        label: "Start automatically",
        icon: "power",
        sensitive: false,
    },
    Perm {
        id: "network",
        label: "Use the internet",
        icon: "globe",
        sensitive: false,
    },
    Perm {
        id: "server",
        label: "Accept incoming connections",
        icon: "globe",
        sensitive: false,
    },
    Perm {
        id: "local_network",
        label: "Devices on your local network",
        icon: "wifi",
        sensitive: false,
    },
    Perm {
        id: "bluetooth",
        label: "Bluetooth",
        icon: "bluetooth",
        sensitive: false,
    },
    Perm {
        id: "usb",
        label: "USB devices",
        icon: "usb",
        sensitive: false,
    },
    Perm {
        id: "programs",
        label: "Start other programs",
        icon: "terminal",
        sensitive: false,
    },
    Perm {
        id: "scripts",
        label: "Run scripts and commands",
        icon: "terminal",
        sensitive: true,
    },
    Perm {
        id: "admin",
        label: "Administrator / system-level actions",
        icon: "shield",
        sensitive: true,
    },
    Perm {
        id: "hardware",
        label: "Talk directly to hardware and drivers",
        icon: "usb",
        sensitive: false,
    },
    Perm {
        id: "tracking",
        label: "Track you across apps and websites",
        icon: "eye",
        sensitive: true,
    },
    Perm {
        id: "speech",
        label: "Speech recognition",
        icon: "mic",
        sensitive: false,
    },
    Perm {
        id: "biometrics",
        label: "Face ID / Touch ID",
        icon: "key",
        sensitive: false,
    },
    Perm {
        id: "health",
        label: "Health data",
        icon: "heart",
        sensitive: true,
    },
    Perm {
        id: "home",
        label: "Smart-home devices",
        icon: "home",
        sensitive: false,
    },
    Perm {
        id: "motion",
        label: "Motion and fitness",
        icon: "heart",
        sensitive: false,
    },
    Perm {
        id: "focus",
        label: "Focus status",
        icon: "eye",
        sensitive: false,
    },
];

fn entitlement_perm(k: &str) -> Option<&'static str> {
    Some(match k.trim_start_matches("com.apple.security.") {
        "device.camera" => "camera",
        "device.audio-input" | "device.microphone" => "microphone",
        "personal-information.location" => "location",
        "personal-information.addressbook" => "contacts",
        "personal-information.calendars" => "calendar",
        "personal-information.photos-library" => "photos",
        "network.client" => "network",
        "network.server" => "server",
        "device.bluetooth" => "bluetooth",
        "device.usb" => "usb",
        "automation.apple-events" | "temporary-exception.apple-events" => "automation",
        "files.user-selected.read-write"
        | "files.user-selected.read-only"
        | "files.downloads.read-write"
        | "files.all"
        | "assets.pictures.read-write"
        | "assets.music.read-write"
        | "assets.movies.read-write" => "files",
        _ => return None,
    })
}

fn behaviour_perm(name: &str) -> Option<&'static [&'static str]> {
    Some(match name {
        "Screen capture" => &["screen"],
        "Keyboard / input monitoring" => &["keyboard"],
        "Camera / microphone" => &["camera", "microphone"],
        "Location" => &["location"],
        "Clipboard" => &["clipboard"],
        "Keychain / credential store" => &["passwords"],
        "Persistence" => &["startup"],
        "Spawns processes" => &["programs"],
        "Runs shell commands" | "Script / AppleScript execution" => &["scripts"],
        "Privilege changes" => &["admin"],
        "Kernel / driver interaction" => &["hardware"],
        "Network sockets" | "HTTP client" => &["network"],
        "File enumeration" | "Deletes files" => &["files"],
        _ => return None,
    })
}

/// What the file may access, merged from entitlements (what the app is
/// allowed), Info.plist explanations (what it asks the person for) and
/// code behaviours (what the code contains).
pub fn permissions(ins: &Value, bundle: Option<&Bundle>, s: &Session) -> Vec<Value> {
    let mut found: BTreeMap<&'static str, (Vec<String>, Option<String>)> = BTreeMap::new();
    let mut add = |id: &'static str, why: String, explain: Option<String>| {
        let e = found.entry(id).or_default();
        if !e.0.contains(&why) {
            e.0.push(why);
        }
        if e.1.is_none() {
            e.1 = explain;
        }
    };
    for kv in ins["signing"]["entitlements"]
        .as_array()
        .into_iter()
        .flatten()
    {
        if let Some(k) = kv[0].as_str()
            && kv[1].as_str() != Some("false")
            && let Some(p) = entitlement_perm(k)
        {
            add(
                p,
                format!(
                    "allowed by the entitlement {}",
                    k.trim_start_matches("com.apple.security.")
                ),
                None,
            );
        }
    }
    if let Some(b) = bundle {
        for (k, text) in &b.usage {
            if let Some((id, _)) = usage_label(k)
                && let Some(p) = PERMS.iter().find(|p| p.id == id)
            {
                add(p.id, "the app asks for it".to_string(), Some(text.clone()));
            }
        }
        if !b.helpers.is_empty() && b.helpers.iter().any(|h| h.ends_with(".app")) {
            add(
                "startup",
                "includes a login item (helper that starts with your Mac)".to_string(),
                None,
            );
        }
    }
    for b in ins["behaviors"].as_array().into_iter().flatten() {
        if let Some(ids) = b["name"].as_str().and_then(behaviour_perm) {
            for id in ids {
                let why = format!(
                    "its code can do this ({})",
                    b["name"].as_str().unwrap_or("")
                );
                if let Some(p) = PERMS.iter().find(|p| p.id == *id) {
                    add(p.id, why, None);
                }
            }
        }
    }
    let _ = s;
    let mut out: Vec<Value> = PERMS
        .iter()
        .filter_map(|p| {
            found.get(p.id).map(|(why, explain)| {
                json!({"id": p.id, "label": p.label, "icon": p.icon, "sensitive": p.sensitive, "why": why, "explanation": explain})
            })
        })
        .collect();
    out.sort_by_key(|p| !p["sensitive"].as_bool().unwrap_or(false));
    out
}

// ---------------------------------------------------------------- maker

pub fn maker(
    s: &Session,
    ins: &Value,
    bundle: Option<&Bundle>,
    cs: Option<&Codesign>,
    exif: Option<&Value>,
) -> Value {
    let mut name: Option<String> = None;
    let mut detail = Vec::<String>::new();
    let mut trust = "unknown";
    if let Some(c) = cs {
        match c.kind.as_str() {
            "apple" => {
                name = Some("Apple".into());
                trust = "verified";
                detail.push("Signed by Apple (part of macOS or an Apple app).".into());
            }
            "app_store" => {
                trust = "verified";
                detail.push("Signed by Apple for the Mac App Store, so Apple reviewed it.".into());
            }
            "developer_id" => {
                name = c.developer.clone();
                trust = if c.notarized { "verified" } else { "signed" };
                detail.push(format!(
                    "Signed with an Apple Developer ID{}.",
                    c.team_id
                        .as_ref()
                        .map(|t| format!(" (team {t})"))
                        .unwrap_or_default()
                ));
                detail.push(if c.notarized {
                    "Apple checked it for known malware (notarized).".into()
                } else {
                    "No notarization ticket is attached; macOS may still check it online.".into()
                });
            }
            "development" => {
                name = c.developer.clone();
                trust = "weak";
                detail.push("Signed with a development certificate: a test build, not meant for distribution.".into());
            }
            "adhoc" => {
                trust = "weak";
                detail.push(
                    "Signed without an identity (ad-hoc): nobody vouches for who made it.".into(),
                );
            }
            "unsigned" => {
                trust = "none";
                detail.push("Not signed: there's no way to tell who made it.".into());
            }
            _ => {
                name = c.developer.clone();
                trust = "signed";
            }
        }
        if let Some(v) = c.valid {
            detail.push(if v {
                "The signature is intact: the app hasn't been changed since it was signed.".into()
            } else {
                format!(
                    "The signature is BROKEN{}: the app was changed after signing.",
                    c.verify_error
                        .as_ref()
                        .map(|e| format!(" ({e})"))
                        .unwrap_or_default()
                )
            });
            if !v {
                trust = "broken";
            }
        }
    } else if let Some(sg) = ins.get("signing").filter(|v| !v.is_null()) {
        if sg["signed"].as_bool() == Some(true) {
            trust = if sg["adhoc"].as_bool() == Some(true) {
                "weak"
            } else {
                "signed"
            };
            if let Some(t) = sg["team_id"].as_str() {
                detail.push(format!("Code-signed by Apple developer team {t}."));
            }
        } else if matches!(s.info.format, Format::Macho | Format::MachoFat) {
            trust = "none";
            detail.push("Not code-signed.".into());
        }
    }
    if matches!(s.info.format, Format::Pe | Format::PeDotnet) {
        let auth = ins["hardening"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|c| c["name"] == "Authenticode");
        match auth.and_then(|a| a["status"].as_str()) {
            Some("good") => {
                trust = "signed";
                detail.push("Has a Windows digital signature (Authenticode). Drishti doesn't check whether Windows trusts it.".into());
            }
            Some(_) => {
                trust = "none";
                detail.push("No Windows digital signature: nobody vouches for who made it.".into());
            }
            None => {}
        }
    }
    if let Some(e) = exif {
        for h in e["data"]["highlights"].as_array().into_iter().flatten() {
            if matches!(h["tag"].as_str(), Some("CompanyName")) && name.is_none() {
                name = h["value"].as_str().map(str::to_string);
                detail.push("The company name comes from the program's version information, which anyone can write.".into());
            }
        }
    }
    if let Some(d) = ins.get("document").filter(|d| !d.is_null()) {
        let meta = |k: &str| {
            d["metadata"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|m| m["key"].as_str().is_some_and(|x| x.eq_ignore_ascii_case(k)))
                .and_then(|m| m["value"].as_str())
                .map(str::to_string)
                .filter(|v| !v.trim().is_empty())
        };
        if name.is_none() {
            name = meta("Author").or_else(|| meta("dc:creator"));
        }
        if let Some(c) = d["clues"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|c| c["topic"] == "made_with")
        {
            detail.push(c["text"].as_str().unwrap_or("").to_string());
        }
        if d["signatures"].as_array().is_some_and(|a| !a.is_empty()) {
            detail.push("It carries a digital signature (see below). Drishti reads the signer's name but doesn't check whether the certificate is trusted.".into());
        } else {
            detail.push(
                "Author names in documents can be typed in by anyone, so treat them as a hint."
                    .into(),
            );
        }
        if trust == "unknown" {
            trust = "document";
        }
    }
    if name.is_none()
        && let Some(b) = bundle
    {
        name = b.copyright.as_deref().and_then(company_from_copyright);
    }
    json!({"name": name, "trust": trust, "detail": detail,
           "app": bundle.map(|b| json!({"name": b.name, "id": b.bundle_id, "version": b.version, "min_os": b.min_os, "copyright": b.copyright,
                                         "root": b.root, "electron": b.asar.is_some(), "frameworks": b.frameworks.len(), "background_only": b.background_only}))})
}

/// "Copyright © 2013-2024 Telegram. All rights reserved." → "Telegram".
pub fn company_from_copyright(c: &str) -> Option<String> {
    let mut t = c.replace(['©', '®'], " ");
    for w in [
        "Copyright",
        "copyright",
        "(c)",
        "(C)",
        "All rights reserved",
        "All Rights Reserved",
        "ALL RIGHTS RESERVED",
    ] {
        t = t.replace(w, " ");
    }
    let t: String = t
        .split_whitespace()
        .filter(|w| {
            !w.trim_matches(|c: char| !c.is_ascii_alphanumeric())
                .chars()
                .all(|c| c.is_ascii_digit() || c == '-')
        })
        .collect::<Vec<_>>()
        .join(" ");
    let t = t
        .trim_matches(|c: char| c == '.' || c == ',' || c == ' ' || c == '-')
        .trim();
    (t.len() >= 2 && t.len() <= 80).then(|| t.to_string())
}

// ---------------------------------------------------------------- grades + verdict

fn grade(score: f64) -> &'static str {
    match score {
        s if s >= 0.9 => "A",
        s if s >= 0.75 => "B",
        s if s >= 0.6 => "C",
        s if s >= 0.4 => "D",
        _ => "F",
    }
}

pub struct Inputs<'a> {
    pub s: &'a Session,
    pub ins: &'a Value,
    pub bundle: Option<&'a Bundle>,
    pub codesign: Option<&'a Codesign>,
    pub tools: &'a [Value],
    pub lookups: &'a [Value],
}

pub fn build(i: Inputs<'_>) -> Value {
    let (hosts, ips) = hosts_and_ips(&i.ins["iocs"]);
    let exif = i.tools.iter().find(|t| t["tool"] == "exiftool");
    let sdk = sdks(i.s, i.bundle, &hosts);
    let perms = permissions(i.ins, i.bundle, i.s);
    let ident = i.ins["signing"]["identifier"].as_str();
    let net = network(&hosts, &ips, i.bundle, ident);
    let who = maker(i.s, i.ins, i.bundle, i.codesign, exif);
    let native = i.s.info.format.is_native();

    // Reasons, strongest first. tone: bad | warn | good | info
    let mut reasons: Vec<(u8, &str, String)> = Vec::new();
    let mut danger = false;
    let mut caution = false;
    for r in i.tools.iter().chain(i.lookups.iter()) {
        let name = r["tool"]
            .as_str()
            .or(r["service"].as_str())
            .unwrap_or("a check");
        let pretty = crate::tools::def(name)
            .map(|t| t.name)
            .unwrap_or(match name {
                "virustotal" => "VirusTotal",
                "malwarebazaar" => "MalwareBazaar",
                "urlhaus" => "URLhaus",
                "abuseipdb" => "AbuseIPDB",
                n => n,
            });
        match r["verdict"].as_str() {
            Some("danger") => {
                danger = true;
                reasons.push((
                    0,
                    "bad",
                    format!(
                        "{pretty}: {}",
                        r["headline"].as_str().unwrap_or("found a problem")
                    ),
                ));
            }
            Some("warning") if name != "exiftool" && name != "jadx" => {
                caution = true;
                reasons.push((
                    2,
                    "warn",
                    format!("{pretty}: {}", r["headline"].as_str().unwrap_or("")),
                ));
            }
            Some("clean") if matches!(name, "virustotal" | "clamav" | "yara" | "malwarebazaar") => {
                reasons.push((
                    6,
                    "good",
                    format!("{pretty}: {}", r["headline"].as_str().unwrap_or("clean")),
                ));
            }
            _ => {}
        }
    }
    if let Some(d) = i.ins.get("document").filter(|d| !d.is_null()) {
        let risky = d["features"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|f| f["severity"] == "high")
            .count();
        if risky > 0 {
            caution = true;
            reasons.push((
                1,
                "bad",
                d["verdict"]
                    .as_str()
                    .unwrap_or("The document contains risky features.")
                    .to_string(),
            ));
        } else {
            reasons.push((
                7,
                "good",
                d["verdict"]
                    .as_str()
                    .unwrap_or("No risky document features found.")
                    .to_string(),
            ));
        }
    }
    match who["trust"].as_str() {
        Some("verified") => reasons.push((
            5,
            "good",
            format!(
                "Made by {} and verified by Apple.",
                who["name"].as_str().unwrap_or("an identified developer")
            ),
        )),
        Some("signed") => reasons.push((
            5,
            "good",
            format!(
                "Signed by {}.",
                who["name"].as_str().unwrap_or("an identified developer")
            ),
        )),
        Some("broken") => {
            danger = true;
            reasons.push((
                0,
                "bad",
                "Its signature is broken: it was changed after the maker signed it.".into(),
            ));
        }
        Some("none") if native => {
            caution = true;
            reasons.push((
                3,
                "warn",
                "Nobody vouches for who made it (no signature).".into(),
            ));
        }
        Some("weak") if native => {
            caution = true;
            reasons.push((
                3,
                "warn",
                "Its signature doesn't identify the maker.".into(),
            ));
        }
        _ => {}
    }
    if i.s.info.is_packed_suspected == Some(true) {
        caution = true;
        reasons.push((
            2,
            "warn",
            "Parts of the code are packed or compressed, which can hide what it does.".into(),
        ));
    }
    let high_beh: Vec<&str> = i.ins["behaviors"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|b| b["severity"] == "high")
        .filter_map(|b| b["name"].as_str())
        .collect();
    if high_beh
        .iter()
        .any(|b| matches!(*b, "Process injection" | "Kernel / driver interaction"))
    {
        caution = true;
        reasons.push((
            2,
            "warn",
            format!(
                "Contains code for powerful actions: {}.",
                high_beh.join(", ").to_lowercase()
            ),
        ));
    }
    let sens: Vec<&str> = perms
        .iter()
        .filter(|p| p["sensitive"] == true)
        .filter_map(|p| p["label"].as_str())
        .collect();
    if !sens.is_empty() {
        reasons.push((
            4,
            "info",
            format!(
                "Can access: {}.",
                sens.iter()
                    .take(5)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
                    .to_lowercase()
            ),
        ));
    }
    let trackers: Vec<&str> = sdk
        .iter()
        .filter(|k| {
            matches!(
                k["category"].as_str(),
                Some("analytics" | "ads" | "attribution")
            )
        })
        .filter_map(|k| k["name"].as_str())
        .collect();
    if !trackers.is_empty() {
        reasons.push((
            4,
            "info",
            format!(
                "Includes {} tracking/advertising kit{} ({}).",
                trackers.len(),
                if trackers.len() == 1 { "" } else { "s" },
                trackers
                    .iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        ));
    }
    reasons.sort_by_key(|r| r.0);
    let scanned = i.tools.iter().chain(i.lookups.iter()).any(|r| {
        matches!(
            r["tool"].as_str().or(r["service"].as_str()),
            Some("yara" | "clamav" | "virustotal" | "malwarebazaar" | "capa")
        )
    });
    let (level, title) = if danger {
        ("danger", "Be careful: this file looks dangerous")
    } else if caution {
        ("caution", "Worth a closer look")
    } else if i.ins.get("document").is_some_and(|d| !d.is_null())
        || who["trust"] == "verified"
        || scanned
    {
        ("good", "Looks normal")
    } else {
        ("unknown", "No warning signs found")
    };
    let mut seen = HashSet::new();
    let reasons: Vec<Value> = reasons
        .into_iter()
        .filter(|r| seen.insert(r.2.clone()))
        .take(6)
        .map(|r| json!({"tone": r.1, "text": r.2}))
        .collect();

    // Grades (only where they mean something).
    let hard = i.ins["hardening"].as_array().cloned().unwrap_or_default();
    let (good, bad) = hard
        .iter()
        .fold((0, 0), |(g, b), c| match c["status"].as_str() {
            Some("good") => (g + 1, b),
            Some("bad") => (g, b + 1),
            _ => (g, b),
        });
    let security = (good + bad > 0).then(|| grade(good as f64 / (good + bad) as f64));
    let trust_grade = match who["trust"].as_str() {
        Some("verified") => Some("A"),
        Some("signed") => Some("B"),
        Some("weak") => Some("D"),
        Some("none") | Some("broken") if native => Some("F"),
        _ => None,
    };
    let privacy = native.then(|| {
        let n_track = trackers.len() as f64;
        let n_sens = sens.len() as f64;
        grade((1.0 - 0.12 * n_track - 0.06 * n_sens).max(0.0))
    });
    json!({
        "verdict": {"level": level, "title": title, "reasons": reasons, "scanned": scanned},
        "maker": who,
        "permissions": perms,
        "network": net,
        "sdks": sdk,
        "grades": {"security": security, "privacy": privacy, "trust": trust_grade},
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts() {
        assert!(host_matches("api.segment.io", "segment.io"));
        assert!(!host_matches("notsegment.io", "segment.io"));
        assert_eq!(host_of("https://a.b.com:443/x").as_deref(), Some("a.b.com"));
        let own = own_domains(None, Some("org.telegram.desktop"));
        assert!(own.contains(&"telegram.org".to_string()));
        assert_eq!(host_category("core.telegram.org", &own).0, "own");
        assert_eq!(host_category("www.w3.org", &own).0, "text");
        assert_eq!(host_category("app-measurement.com", &own).0, "tracking");
        assert_eq!(grade(1.0), "A");
        assert_eq!(
            company_from_copyright("Copyright © 2013-2024 Telegram. All rights reserved.")
                .as_deref(),
            Some("Telegram")
        );
        assert_eq!(
            company_from_copyright("© 2024 Google LLC").as_deref(),
            Some("Google LLC")
        );
        let own = own_domains(None, Some("ru.keepcoder.Telegram"));
        assert_eq!(host_category("core.telegram.org", &own).0, "own");
        assert_eq!(grade(0.1), "F");
    }
}
