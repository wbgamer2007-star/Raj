# পেজ ম্যানেজার: ধাপ ১

এই ধাপে যা আছে: অ্যাডমিন ও কর্মচারীর লগইন, কর্মচারী অ্যাকাউন্ট বানানো, client যোগ করা (১ client = ১ Facebook Page), Page-এর টোকেন Facebook-এ যাচাই, client-এর ফোন নম্বর, অর্ডারের ধরন, AI-এর নির্দেশ ও নিজস্ব Gemini key রাখা, কাজের রেকর্ড।

**এই ধাপে এখনো নেই:** Messenger-এ AI-এর উত্তর, কমেন্ট, পোস্ট, অর্ডার। এগুলো পরের ধাপে আসবে। client-এর পাতায় "মেসেজ গ্রহণ: এখনো চালু হয়নি" লেখা থাকবে, সেটা ঠিক।

## ১. গোপন key বানান
কম্পিউটার বা Termux-এ (Python থাকলে):
```
python make_keys.py
```
দুই লাইনের ফল আসবে (SECRET_KEY আর ENCRYPTION_KEY)। দুটোই নিরাপদ জায়গায় লিখে রাখুন।
**ENCRYPTION_KEY হারালে client-দের সংরক্ষিত টোকেন আর খোলা যাবে না,** তখন সবার টোকেন নতুন করে দিতে হবে।

## ২. Firebase ঠিক করুন
1. console.firebase.google.com এ গিয়ে নতুন প্রজেক্ট বানান।
2. বাঁদিকের **Build → Firestore Database → Create database**। এখানে অঞ্চল (region) বেছে নিতে হয় এবং পরে বদলানো যায় না। বাংলাদেশের কাছের কিছু বেছে নিন (যেমন Singapore বা Mumbai)।
3. Firestore-এর **Rules** ট্যাবে এই লেখা বসিয়ে Publish করুন (আমাদের সার্ভার ছাড়া আর কেউ ডেটা ছুঁতে পারবে না):
```
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} { allow read, write: if false; }
  }
}
```
4. ওপরে ⚙️ (Project settings) → **Service accounts → Generate new private key**। একটা JSON ফাইল নামবে। এই ফাইল কাউকে দেবেন না, GitHub-এও তুলবেন না।

## ৩. GitHub-এ কোড তুলুন
এই ফোল্ডারের সব ফাইল একটা **Private** GitHub repository-তে আপলোড করুন।

## ৪. Render-এ চালু করুন
1. render.com → **New → Web Service** → আপনার repository বেছে নিন।
2. Build Command: `pip install -r requirements.txt`
3. Start Command: `gunicorn wsgi:app --workers 1 --threads 4 --timeout 60`
4. **Environment** অংশে এগুলো বসান:

| নাম | মান |
|---|---|
| SECRET_KEY | ধাপ ১ থেকে |
| ENCRYPTION_KEY | ধাপ ১ থেকে |
| ADMIN_USERNAME | আপনার পছন্দের ইউজারনেম |
| ADMIN_PASSWORD | শক্ত পাসওয়ার্ড (১০ অক্ষরের বেশি) |
| FIREBASE_SERVICE_ACCOUNT_JSON | ডাউনলোড করা JSON ফাইলের **পুরো লেখা** |
| BASE_URL | Render আপনাকে যে ঠিকানা দেবে (https://....onrender.com) |
| META_GRAPH_API_VERSION | v26.0 |
| PYTHON_VERSION | 3.12.3 |

5. প্রথমবার চালুর পর Render-এর ঠিকানাটা BASE_URL-এ বসিয়ে আবার Deploy করুন। না করলে লগইন-কুকি কম নিরাপদ থাকে।
6. Health Check Path হিসেবে `/health` দিন।

কোনো মান ভুল বা বাদ থাকলে অ্যাপ চালুই হবে না, আর Render-এর Logs-এ বাংলায় লেখা থাকবে কোনটা ঠিক নেই।

## ৫. প্রথম ব্যবহার
1. ঠিকানায় গিয়ে ADMIN_USERNAME ও পাসওয়ার্ড দিয়ে ঢুকুন।
2. **Client → নতুন client**: নাম, Page ID আর Page Access Token দিন। সিস্টেম Facebook-কে জিজ্ঞেস করে নিশ্চিত হবে যে টোকেনটা ওই Page-এরই। ভুল হলে client যোগ হবে না।
3. **কর্মচারী → নতুন কর্মচারী**: ইমেইল, পাসওয়ার্ড দিন এবং কোন কোন client সে দেখবে বেছে দিন।

টোকেন নিয়ে একটা কথা: Graph API Explorer থেকে নেওয়া টোকেন অল্প সময় পরে অচল হয়ে যায়। দীর্ঘস্থায়ী টোকেন পাওয়ার সঠিক পথ পরের ধাপে যোগ হবে।

## পরীক্ষা চালানো
```
python -m unittest discover -s tests -v
```
এই পরীক্ষাগুলোতে Facebook-এর উত্তর **নকল** এবং ডেটাবেস **মেমরির**। এগুলো আসল Facebook বা আসল Firestore পরীক্ষা নয়।

## পরীক্ষার ডেভেলপমেন্ট মোড (কম্পিউটারে)
FIREBASE_SERVICE_ACCOUNT_JSON না দিয়ে `ALLOW_MEMORY_STORE=1` দিলে মেমরি ডেটাবেসে চলে। তখন প্রতিটি পাতায় লাল সতর্কতা দেখায় এবং সার্ভার বন্ধ হলে সব ডেটা যায়। আসল কাজে এটা কখনো ব্যবহার করবেন না।

## সীমাবদ্ধতা (জেনে রাখুন)
- লগইনে ভুল চেষ্টা আটকানোর গণনা সার্ভারের মেমরিতে থাকে। সার্ভার রিস্টার্ট হলে গণনা শূন্য হয়।
- Render-এর ফ্রি সার্ভার কিছুক্ষণ ব্যবহার না হলে ঘুমিয়ে যায়, প্রথম অনুরোধে দেরি হয়।
- Firebase-এ ব্যাকআপ আলাদাভাবে রাখা নেই। এটা পরে যোগ করা উচিত।
