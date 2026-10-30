"""Facebook Graph API-র সাথে যোগাযোগ। এখানে কোনো নকল উত্তর নেই।"""
import requests


def validate_page_token(page_id, token, version):
    """Page token সত্যিই ওই Page-এর কি না Facebook-কে জিজ্ঞেস করে।
    ফেরত দেয়: (ঠিক আছে কি না, Page-এর নাম, ভুলের বার্তা)"""
    url = f"https://graph.facebook.com/{version}/me"
    try:
        r = requests.get(url, params={"fields": "id,name", "access_token": token}, timeout=10)
    except requests.RequestException:
        return False, None, "Facebook-এ পৌঁছানো যায়নি। একটু পরে আবার চেষ্টা করুন।"
    try:
        data = r.json()
    except ValueError:
        data = {}
    if r.status_code != 200 or "error" in data:
        msg = str((data.get("error") or {}).get("message", "অজানা সমস্যা")).replace(token, "***")
        return False, None, f"Facebook টোকেনটি গ্রহণ করেনি: {msg}"
    if str(data.get("id")) != str(page_id):
        return False, None, "এই টোকেন অন্য Page বা অন্য অ্যাকাউন্টের। ঠিক Page-এর Page Access Token দিন।"
    return True, data.get("name") or "", None
