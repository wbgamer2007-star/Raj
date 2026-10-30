"""এনক্রিপশন ও লগইনে বারবার চেষ্টা আটকানো।"""
import threading
import time

from cryptography.fernet import Fernet


class Crypto:
    """Page token ও Gemini key এনক্রিপ্ট করে রাখার জন্য। key ভুল হলে শুরুতেই ব্যর্থ হয়।"""

    def __init__(self, key):
        self._f = Fernet(key)

    def encrypt(self, text):
        return self._f.encrypt(text.encode("utf-8")).decode("ascii")

    def decrypt(self, token):
        return self._f.decrypt(token.encode("ascii")).decode("utf-8")


class RateLimiter:
    """একই ব্যক্তি/আইপি থেকে ১৫ মিনিটে ৫ বার ভুল করলে আটকে দেয়।
    মেমরিতে থাকে, তাই সার্ভার রিস্টার্ট হলে গণনা শূন্য হয়।"""

    def __init__(self, max_attempts=5, window=900):
        self.max = max_attempts
        self.window = window
        self._fails = {}
        self._lock = threading.Lock()

    def _prune(self, key, now):
        self._fails[key] = [t for t in self._fails.get(key, []) if now - t < self.window]

    def blocked(self, key):
        with self._lock:
            now = time.time()
            self._prune(key, now)
            return len(self._fails[key]) >= self.max

    def fail(self, key):
        with self._lock:
            now = time.time()
            self._prune(key, now)
            self._fails[key].append(now)

    def reset(self, key):
        with self._lock:
            self._fails.pop(key, None)
