"""দুটো গোপন key বানায়। শুধু একবার চালান, ফলাফল নিরাপদ জায়গায় রাখুন।
চালাতে: python make_keys.py
"""
import base64
import os
import secrets

print("SECRET_KEY=" + secrets.token_urlsafe(48))
print("ENCRYPTION_KEY=" + base64.urlsafe_b64encode(os.urandom(32)).decode())
