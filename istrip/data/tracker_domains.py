"""
Comprehensive list of known tracking, analytics, and telemetry domains.
These are used for:
  1. DNS-level blocking via mobileconfig profile generation
  2. Network traffic auditing (pcap analysis)
  3. App-level tracking detection
"""

# Apple's own telemetry / analytics domains
APPLE_ANALYTICS = [
    "metrics.icloud.com",
    "metrics.mzstatic.com",
    "xp.apple.com",
    "securemetrics.apple.com",
    "supportmetrics.apple.com",
    "diagnostics.apple.com",
    "idiagnostics.apple.com",
    "analytics.apple.com",
    "iphonesubmissions.apple.com",
    "radarsubmissions.apple.com",
    "books-analytics-events.apple.com",
    "news-analytics-events.apple.com",
    "weather-analytics-events.apple.com",
    "stocks-analytics-events.apple.com",
    "notes-analytics-events.apple.com",
    "fitness-analytics-events.apple.com",
    "health-analytics-events.apple.com",
    "wallet-analytics-events.apple.com",
    "maps-analytics-events.apple.com",
    "music-analytics-events.apple.com",
    "podcasts-analytics-events.apple.com",
    "tv-analytics-events.apple.com",
    "messages-analytics-events.apple.com",
    "mail-analytics-events.apple.com",
    "photos-analytics-events.apple.com",
    "siri-analytics-events.apple.com",
    "facetime-analytics-events.apple.com",
    "appstore-analytics-events.apple.com",
    "safari-analytics-events.apple.com",
    "keyvalueservice.icloud.com",
    "experiment.apple.com",
    "api-adservices.apple.com",
    "advertising.apple.com",
    "searchads.apple.com",
    "iad.apple.com",
    "iadsdk.apple.com",
    "tr.iadsdk.apple.com",
    "banners.itunes.apple.com",
    "token.safebrowsing.apple",
]

# Major third-party ad/tracking networks
AD_NETWORKS = [
    # Google
    "pagead2.googlesyndication.com",
    "adservice.google.com",
    "googleads.g.doubleclick.net",
    "www.googleadservices.com",
    "googleadapis.l.google.com",
    "ad.doubleclick.net",
    "stats.g.doubleclick.net",
    "cm.g.doubleclick.net",
    "securepubads.g.doubleclick.net",
    "partnerad.l.doubleclick.net",
    # Facebook/Meta
    "an.facebook.com",
    "pixel.facebook.com",
    "www.facebook.com/tr",
    "connect.facebook.net",
    "graph.facebook.com",
    "ad.atdmt.com",
    # Amazon
    "aax.amazon-adsystem.com",
    "z-na.amazon-adsystem.com",
    "fls-na.amazon-adsystem.com",
    # Microsoft
    "ads.msn.com",
    "adnxs.com",
    "bat.bing.com",
    "c.msn.com",
    "ui.skype.com",
    # Twitter/X
    "ads-api.twitter.com",
    "ads-twitter.com",
    "analytics.twitter.com",
    "t.co",
    # TikTok
    "analytics.tiktok.com",
    "ads.tiktok.com",
    "log.tiktokv.com",
    "mon.tiktokv.com",
    # Snapchat
    "tr.snapchat.com",
    "sc-analytics.appspot.com",
    "ads.snapchat.io",
    # LinkedIn
    "ads.linkedin.com",
    "analytics.pointdrive.linkedin.com",
]

# Mobile-specific analytics/attribution SDKs
MOBILE_SDKS = [
    # Adjust
    "app.adjust.com",
    "app.adjust.io",
    "app.adjust.net.in",
    "app.adjust.world",
    "app.apptrace.com",
    # AppsFlyer
    "t.appsflyer.com",
    "launches.appsflyer.com",
    "conversions.appsflyer.com",
    "impression.appsflyer.com",
    "onelink.appsflyer.com",
    "sdk.appsflyer.com",
    # Branch
    "api2.branch.io",
    "cdn.branch.io",
    "bnc.lt",
    # Kochava
    "control.kochava.com",
    "imp.control.kochava.com",
    # Singular
    "sdk-api-v1.singular.net",
    "s2s.singular.net",
    # Unity Ads
    "unityads.unity3d.com",
    "config.unityads.unity3d.com",
    "adserver.unityads.unity3d.com",
    # ironSource
    "outcome-ssp.supersonicads.com",
    "init.supersonicads.com",
    # Flurry
    "data.flurry.com",
    "ads.flurry.com",
    # Mixpanel
    "api.mixpanel.com",
    "decide.mixpanel.com",
    # Amplitude
    "api2.amplitude.com",
    "api.amplitude.com",
    # Segment
    "api.segment.io",
    "cdn.segment.com",
    # Firebase Analytics
    "app-measurement.com",
    "firebase-settings.crashlytics.com",
    "sessions.crashlytics.com",
    # Crashlytics
    "settings.crashlytics.com",
    "reports.crashlytics.com",
    # Braze
    "sdk.iad-01.braze.com",
    "sdk.iad-03.braze.com",
    # CleverTap
    "wzrkt.com",
    "in.wzrkt.com",
    # OneSignal
    "onesignal.com",
    "api.onesignal.com",
    # Leanplum
    "api.leanplum.com",
    "dev.leanplum.com",
    # MoEngage
    "sdk-01.moengage.com",
    "sdk.moengage.com",
]

# Fingerprinting / cross-device tracking
FINGERPRINTING = [
    # Device fingerprinting
    "api.adsrvr.org",
    "match.adsrvr.org",
    "insight.adsrvr.org",
    "id5-sync.com",
    "id.sharedid.org",
    "prebid.adnxs.com",
    "ib.adnxs.com",
    "eus.rubiconproject.com",
    "fastlane.rubiconproject.com",
    "pixel.rubiconproject.com",
    "sync.outbrain.com",
    "widgets.outbrain.com",
    "log.outbrain.com",
    "api.taboola.com",
    "trc.taboola.com",
    "nr-data.net",
    "cdn.taboola.com",
    "simage2.pubmatic.com",
    "hbopenbid.pubmatic.com",
    "image8.pubmatic.com",
    "t.pubmatic.com",
]

# Location tracking services
LOCATION_TRACKING = [
    "location.services.mozilla.com",
    "ls.apple.com",
    "gs-loc.apple.com",
    "gsp-ssl.ls.apple.com",
    "gsp64-ssl.ls.apple.com",
    "gspe1-ssl.ls.apple.com",
    "gspe35-ssl.ls.apple.com",
    "play.googleapis.com",
    "www.googleapis.com",
    "clients4.google.com",
    "safebrowsing.googleapis.com",
    "skyhookwireless.com",
    "api.skyhookwireless.com",
    "navizon.com",
    "api.combain.com",
    "unwiredlabs.com",
    "foursquare.com",
]

# Data brokers and cross-site trackers
DATA_BROKERS = [
    "adsymptotic.com",
    "adform.net",
    "serving-sys.com",
    "eyeota.net",
    "krxd.net",
    "bluekai.com",
    "addthis.com",
    "exelator.com",
    "agkn.com",
    "rlcdn.com",
    "demdex.net",
    "crwdcntrl.net",
    "liveramp.com",
    "acxiom.com",
    "oracle.com/cx",
    "owneriq.net",
    "lotame.com",
    "sharethrough.com",
    "casalemedia.com",
    "mathtag.com",
    "scorecardresearch.com",
    "quantserve.com",
    "imrworldwide.com",
    "moatads.com",
    "doubleverify.com",
]

# Carrier / ISP tracking
CARRIER_TRACKING = [
    "data.mistat.intl.xiaomi.com",
    "data.mistat.xiaomi.com",
    "tracking.miui.com",
    "sa.api.intl.miui.com",
    "globalapi.ad.xiaomi.com",
    "sdkconfig.ad.xiaomi.com",
    "connect.facebook.net",
    "events.appsflyer.com",
]


def get_all_tracker_domains() -> list[str]:
    """Return a deduplicated, sorted list of all known tracker domains."""
    all_domains = set()
    for domain_list in [
        APPLE_ANALYTICS,
        AD_NETWORKS,
        MOBILE_SDKS,
        FINGERPRINTING,
        LOCATION_TRACKING,
        DATA_BROKERS,
        CARRIER_TRACKING,
    ]:
        all_domains.update(domain_list)
    return sorted(all_domains)


def get_domains_by_category() -> dict[str, list[str]]:
    """Return tracker domains organized by category."""
    return {
        "Apple Analytics & Telemetry": APPLE_ANALYTICS,
        "Ad Networks": AD_NETWORKS,
        "Mobile SDK Trackers": MOBILE_SDKS,
        "Fingerprinting & Cross-Device": FINGERPRINTING,
        "Location Tracking": LOCATION_TRACKING,
        "Data Brokers": DATA_BROKERS,
        "Carrier/OEM Tracking": CARRIER_TRACKING,
    }
