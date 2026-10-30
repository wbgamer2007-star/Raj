"""ডেটা রাখার স্তর। আসল কাজে Firestore, পরীক্ষা/ডেভেলপমেন্টে মেমরি।

দুটোর মেথড একই, তাই বাকি কোড জানে না কোনটা চলছে।
"""
import copy
import threading
import uuid
from datetime import datetime, timezone


class AlreadyExists(Exception):
    """create() করার সময় ওই আইডির ডকুমেন্ট আগেই থাকলে।"""


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class MemoryStore:
    """শুধু পরীক্ষা বা ডেভেলপমেন্টের জন্য। সার্ভার বন্ধ হলে সব মুছে যায়।"""

    kind = "memory"

    def __init__(self):
        self._d = {}
        self._lock = threading.RLock()

    def get(self, coll, doc_id):
        with self._lock:
            v = self._d.get(coll, {}).get(doc_id)
            return None if v is None else {**copy.deepcopy(v), "id": doc_id}

    def create(self, coll, doc_id, data):
        with self._lock:
            c = self._d.setdefault(coll, {})
            if doc_id in c:
                raise AlreadyExists(doc_id)
            c[doc_id] = copy.deepcopy(data)

    def set(self, coll, doc_id, data):
        with self._lock:
            self._d.setdefault(coll, {})[doc_id] = copy.deepcopy(data)

    def update(self, coll, doc_id, data):
        with self._lock:
            c = self._d.setdefault(coll, {})
            if doc_id not in c:
                raise KeyError(doc_id)
            c[doc_id].update(copy.deepcopy(data))

    def delete(self, coll, doc_id):
        with self._lock:
            self._d.get(coll, {}).pop(doc_id, None)

    def list(self, coll):
        with self._lock:
            return [{**copy.deepcopy(v), "id": k} for k, v in self._d.get(coll, {}).items()]

    def add(self, coll, data):
        doc_id = uuid.uuid4().hex
        self.create(coll, doc_id, data)
        return doc_id


class FirestoreStore:
    """Google Firestore। প্রতিটি মেথড সত্যিকারের ডেটাবেসে কাজ করে।"""

    kind = "firestore"

    def __init__(self, service_account_info):
        from google.cloud import firestore

        self._db = firestore.Client.from_service_account_info(service_account_info)

    def _ref(self, coll, doc_id):
        return self._db.collection(coll).document(doc_id)

    def get(self, coll, doc_id):
        snap = self._ref(coll, doc_id).get()
        if not snap.exists:
            return None
        return {**snap.to_dict(), "id": doc_id}

    def create(self, coll, doc_id, data):
        from google.api_core.exceptions import AlreadyExists as _AE

        try:
            self._ref(coll, doc_id).create(data)
        except _AE as e:
            raise AlreadyExists(doc_id) from e

    def set(self, coll, doc_id, data):
        self._ref(coll, doc_id).set(data)

    def update(self, coll, doc_id, data):
        from google.api_core.exceptions import NotFound

        try:
            self._ref(coll, doc_id).update(data)
        except NotFound as e:
            raise KeyError(doc_id) from e

    def delete(self, coll, doc_id):
        self._ref(coll, doc_id).delete()

    def list(self, coll):
        return [{**s.to_dict(), "id": s.id} for s in self._db.collection(coll).stream()]

    def add(self, coll, data):
        doc_id = uuid.uuid4().hex
        self.create(coll, doc_id, data)
        return doc_id
