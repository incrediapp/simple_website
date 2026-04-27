const crypto = require("crypto");
const { onRequest } = require("firebase-functions/v2/https");
const { error: logError } = require("firebase-functions/logger");
const { initializeApp } = require("firebase-admin/app");
const { getFirestore, Timestamp } = require("firebase-admin/firestore");

initializeApp();

const db = getFirestore();
const WINDOW_MS = 10 * 60 * 1000;
const FORMSUBMIT_URL = "https://formsubmit.co/support@incrediapp.com";

function clientIp(req) {
  const xff = req.headers["x-forwarded-for"];
  if (typeof xff === "string" && xff.length > 0) {
    return xff.split(",")[0].trim();
  }
  const xReal = req.headers["x-real-ip"];
  if (typeof xReal === "string" && xReal.length > 0) {
    return xReal.trim();
  }
  return req.socket?.remoteAddress || "unknown";
}

function hashIp(ip) {
  return crypto.createHash("sha256").update(ip, "utf8").digest("hex");
}

function normStr(value, max) {
  if (typeof value !== "string") {
    return "";
  }
  return value.trim().slice(0, max);
}

function isValidEmail(email) {
  return (
    typeof email === "string" &&
    email.length <= 320 &&
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
  );
}

exports.submitDeletionRequest = onRequest(
  {
    region: "us-central1",
    cors: true,
    invoker: "public",
  },
  async (req, res) => {
    if (req.method === "OPTIONS") {
      res.status(204).send("");
      return;
    }
    if (req.method !== "POST") {
      res.status(405).json({ error: "Method not allowed" });
      return;
    }

    const body = req.body && typeof req.body === "object" ? req.body : {};
    const honeypot = normStr(body.website, 200) + normStr(body._gotcha, 200);
    if (honeypot.length > 0) {
      res.status(200).json({ ok: true });
      return;
    }

    const appName = normStr(body.appName, 200);
    const email = normStr(body.email, 320);

    if (!appName) {
      res.status(400).json({ error: "App name is required" });
      return;
    }
    if (!isValidEmail(email)) {
      res.status(400).json({ error: "A valid email is required" });
      return;
    }

    const ip = clientIp(req);
    const ipHash = hashIp(ip);
    const ref = db.collection("deletionRateLimits").doc(ipHash);

    let blocked = false;
    let retryAfterSec = 0;
    let rollbackLastAt = undefined;

    try {
      await db.runTransaction(async (t) => {
        const snap = await t.get(ref);
        const now = Date.now();
        if (snap.exists) {
          const lastAt = snap.data().lastAt;
          const lastMs =
            lastAt && typeof lastAt.toMillis === "function" ? lastAt.toMillis() : 0;
          if (now - lastMs < WINDOW_MS) {
            blocked = true;
            retryAfterSec = Math.ceil((WINDOW_MS - (now - lastMs)) / 1000);
            return;
          }
          rollbackLastAt = lastAt || null;
        } else {
          rollbackLastAt = null;
        }
        t.set(ref, { lastAt: Timestamp.fromMillis(now) }, { merge: true });
      });
    } catch (e) {
      logError("Rate limit transaction failed", e);
      const code = e && e.code;
      const msg = String((e && e.message) || e || "");
      const looksMissingDb =
        code === 5 ||
        code === "NOT_FOUND" ||
        /database.*not found|does not exist|Firestore.*not.*enabled|NOT_FOUND/i.test(msg);
      const looksDenied = code === 7 || code === "PERMISSION_DENIED";
      let userMsg =
        "Could not process request (server storage error). Throttling would show a 'try again in X minutes' message instead.";
      if (looksMissingDb) {
        userMsg =
          "Firestore is not enabled or no database exists yet. Firebase console → Build → Firestore Database → Create database, then run: firebase deploy --only firestore,functions";
      } else if (looksDenied) {
        userMsg =
          "Firestore permission denied for the Cloud Function service account. Check IAM (roles like Cloud Datastore User) for the function's runtime identity.";
      }
      res.status(500).json({ error: userMsg });
      return;
    }

    if (blocked) {
      res.status(429).json({
        error: "Error submitting request. Please try again later.",
        retryAfterSec,
      });
      return;
    }

    const params = new URLSearchParams();
    params.set("_subject", "Data deletion request — IncrediApp");
    params.set("_template", "table");
    params.set("_captcha", "false");
    params.set("Email", email);
    params.set("App name", appName);

    try {
      const upstream = await fetch(FORMSUBMIT_URL, {
        method: "POST",
        headers: {
          Accept: "text/html",
          "Content-Type": "application/x-www-form-urlencoded",
          "User-Agent": "IncrediApp-deletion-form/1.0",
        },
        body: params.toString(),
        redirect: "manual",
      });

      if (upstream.status >= 400) {
        throw new Error(`FormSubmit HTTP ${upstream.status}`);
      }
    } catch (e) {
      logError("FormSubmit relay failed", e);
      try {
        if (rollbackLastAt === null) {
          await ref.delete();
        } else if (rollbackLastAt) {
          await ref.set({ lastAt: rollbackLastAt }, { merge: true });
        }
      } catch (rollbackErr) {
        logError("Rollback failed", rollbackErr);
      }
      res.status(502).json({
        error: "Could not deliver request. Please try again or email support@incrediapp.com.",
      });
      return;
    }

    res.status(200).json({ ok: true });
  }
);
