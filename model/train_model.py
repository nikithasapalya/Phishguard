"""
train_model.py — Balanced training pipeline.

Run from anywhere:
    python model/train_model.py
or:
    cd model && python train_model.py
"""
import os
import sys
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# Make `feature_extractor` importable no matter where we run from
THIS_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, THIS_DIR)
from feature_extractor import features_to_list  # noqa: E402

PROJECT_ROOT = os.path.dirname(THIS_DIR)
DATASET_PATH = os.path.join(PROJECT_ROOT, "data", "phishing_dataset.csv")
MODEL_OUT  = os.path.join(THIS_DIR, "phishing_model.pkl")
SCALER_OUT = os.path.join(THIS_DIR, "scaler.pkl")


# A diverse legitimate-URL corpus so the model learns "safe DNA" properly.
# Including paths/subdomains gives the model real structural variety.
# A diverse legitimate-URL corpus so the model learns "safe DNA" properly.
# Includes paths/subdomains so the model sees real structural variety.
LEGIT_URLS = [
    # Search / portals
    "https://www.google.com", "https://www.google.co.in/search?q=phishing",
    "https://mail.google.com/mail/u/0/#inbox", "https://drive.google.com/drive/my-drive",
    "https://maps.google.com", "https://translate.google.com",
    "https://www.bing.com", "https://duckduckgo.com", "https://www.yahoo.com",
    # YouTube / Google services
    "https://www.youtube.com", "https://www.youtube.com/watch?v=dQw4w9WgXcQ",
    "https://www.youtube.com/feed/trending", "https://m.youtube.com",
    "https://music.youtube.com", "https://studio.youtube.com",
    # Wikipedia / education
    "https://www.wikipedia.org", "https://en.wikipedia.org/wiki/Phishing",
    "https://en.wikipedia.org/wiki/Main_Page", "https://www.khanacademy.org",
    "https://www.coursera.org/learn/machine-learning",
    "https://www.udemy.com/course/python", "https://www.edx.org",
    "https://www.geeksforgeeks.org/python-programming-language/",
    "https://www.w3schools.com/html/", "https://leetcode.com/problemset/all/",
    # Social
    "https://www.facebook.com", "https://www.facebook.com/zuck",
    "https://www.instagram.com", "https://www.instagram.com/explore/",
    "https://twitter.com", "https://x.com/elonmusk",
    "https://www.linkedin.com", "https://www.linkedin.com/in/satyanadella/",
    "https://www.linkedin.com/jobs/", "https://www.reddit.com",
    "https://www.reddit.com/r/cybersecurity/", "https://www.pinterest.com",
    "https://www.tiktok.com", "https://discord.com/channels/@me",
    "https://web.whatsapp.com", "https://t.me/durov",
    # Tech / dev
    "https://www.github.com", "https://github.com/torvalds/linux",
    "https://github.com/microsoft/vscode/issues", "https://gitlab.com",
    "https://bitbucket.org", "https://stackoverflow.com",
    "https://stackoverflow.com/questions/tagged/python",
    "https://www.python.org", "https://docs.python.org/3/library/os.html",
    "https://nodejs.org/en", "https://reactjs.org", "https://vuejs.org",
    "https://angular.io", "https://developer.mozilla.org/en-US/docs/Web/JavaScript",
    "https://www.npmjs.com/package/react", "https://pypi.org/project/scikit-learn/",
    "https://hub.docker.com", "https://kubernetes.io/docs/home/",
    # Cloud / SaaS
    "https://www.cloudflare.com", "https://aws.amazon.com",
    "https://console.aws.amazon.com", "https://cloud.google.com",
    "https://console.cloud.google.com", "https://azure.microsoft.com",
    "https://portal.azure.com", "https://www.digitalocean.com",
    "https://www.heroku.com", "https://vercel.com/dashboard",
    "https://www.netlify.com", "https://render.com",
    # Microsoft / Apple
    "https://www.microsoft.com", "https://www.office.com",
    "https://outlook.live.com/mail/0/", "https://www.bing.com/maps",
    "https://learn.microsoft.com/en-us/azure/", "https://teams.microsoft.com",
    "https://www.apple.com", "https://support.apple.com/en-in",
    "https://www.icloud.com", "https://developer.apple.com",
    # Streaming / media
    "https://www.netflix.com", "https://www.netflix.com/in/title/80100172",
    "https://www.primevideo.com", "https://www.hotstar.com",
    "https://www.disneyplus.com", "https://www.spotify.com",
    "https://open.spotify.com/genre/charts", "https://soundcloud.com",
    "https://www.twitch.tv", "https://vimeo.com",
    # News
    "https://www.bbc.com/news", "https://www.bbc.co.uk",
    "https://www.cnn.com", "https://www.nytimes.com",
    "https://www.theguardian.com/international", "https://www.reuters.com",
    "https://www.bloomberg.com", "https://www.ndtv.com",
    "https://www.thehindu.com", "https://www.hindustantimes.com",
    "https://timesofindia.indiatimes.com", "https://www.indiatoday.in",
    # Shopping
    "https://www.amazon.com", "https://www.amazon.in",
    "https://www.amazon.in/gp/your-account", "https://www.flipkart.com",
    "https://www.myntra.com", "https://www.ebay.com", "https://www.walmart.com",
    "https://www.alibaba.com", "https://www.aliexpress.com",
    "https://www.shopify.com", "https://www.meesho.com",
    "https://www.ajio.com", "https://www.nykaa.com",
    # Indian banks / fintech / govt
    "https://www.sbi.co.in", "https://onlinesbi.sbi",
    "https://www.hdfcbank.com", "https://www.hdfcbank.com/personal",
    "https://www.icicibank.com", "https://www.axisbank.com",
    "https://www.kotak.com", "https://www.yesbank.in",
    "https://www.rbi.org.in", "https://uidai.gov.in",
    "https://www.incometax.gov.in", "https://www.india.gov.in",
    "https://www.irctc.co.in", "https://epfindia.gov.in",
    "https://paytm.com", "https://www.phonepe.com",
    "https://razorpay.com", "https://cred.club",
    # Global fintech
    "https://www.paypal.com", "https://www.paypal.com/in/home",
    "https://stripe.com", "https://wise.com", "https://www.visa.com",
    "https://www.mastercard.com", "https://www.americanexpress.com",
    # Food / travel
    "https://www.swiggy.com", "https://www.zomato.com",
    "https://www.ubereats.com", "https://www.uber.com", "https://www.olacabs.com",
    "https://www.makemytrip.com", "https://www.goibibo.com",
    "https://www.booking.com", "https://www.airbnb.com",
    # Yenepoya University & affiliated portals
    "https://yenepoya.edu.in", "https://yenepoya.edu.in/about",
    "https://student.yenepoya.edu.in/", "https://student.yenepoya.edu.in/login",
    "https://ytincubator.com/", "https://ytincubator.com/about",
    "https://yengage.yenepoya.edu.in/", "https://yengage.yenepoya.edu.in/login",
    "https://vidyen.yenepoya.in/", "https://vidyen.yenepoya.in/courses",
    "https://www.ydc.yenepoya.edu.in/", "https://www.ydc.yenepoya.edu.in/about",
]


def train_production_model() -> None:
    print("[*] Starting balanced training pipeline...")

    if not os.path.exists(DATASET_PATH):
        raise FileNotFoundError(
            f"Dataset not found at {DATASET_PATH}. "
            f"Place phishing_dataset.csv in the data/ folder."
        )

    df_phish = pd.read_csv(DATASET_PATH)
    url_col = "URL" if "URL" in df_phish.columns else (
        "url" if "url" in df_phish.columns else df_phish.columns[0]
    )
    df_phish = df_phish[[url_col]].dropna().head(5000).copy()
    df_phish.columns = ["URL"]
    df_phish["label"] = 1

    # Build the legitimate side: ~5000 rows, sampled with replacement so
    # weights are balanced AND the model sees real diversity.
    df_safe = pd.DataFrame({"URL": (LEGIT_URLS * (5000 // len(LEGIT_URLS) + 1))[:5000]})
    df_safe["label"] = 0

    df = pd.concat([df_phish, df_safe], ignore_index=True).sample(
        frac=1, random_state=42
    ).reset_index(drop=True)

    print(f"[*] Extracting 21 features from {len(df)} URLs "
          f"({(df.label==1).sum()} phishing / {(df.label==0).sum()} safe)...")

    X = [features_to_list(str(u), is_training=True) for u in df["URL"]]
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_test_s  = scaler.transform(X_test)

    print("[*] Training Random Forest...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=20,
        min_samples_leaf=2,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    model.fit(X_train_s, y_train)

    print("\nClassification report on held-out test set:")
    print(classification_report(y_test, model.predict(X_test_s),
                                target_names=["legitimate", "phishing"]))

    joblib.dump(model,  MODEL_OUT)
    joblib.dump(scaler, SCALER_OUT)
    print(f"[OK] Saved model  -> {MODEL_OUT}")
    print(f"[OK] Saved scaler -> {SCALER_OUT}")


if __name__ == "__main__":
    train_production_model()
