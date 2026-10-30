"""ধাপ ১-এর স্বয়ংক্রিয় পরীক্ষা।

সতর্কতা: এখানে Facebook-এর উত্তর নকল (mock) করা হয়েছে এবং ডেটাবেস মেমরির।
এগুলো আসল Facebook বা আসল Firestore পরীক্ষা নয়।
"""
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.fernet import Fernet  # noqa: E402

from app import create_app  # noqa: E402
from store import MemoryStore  # noqa: E402

FAKE_TOKEN = "EAAB-fake-page-token-1234567890-abcdef"
FAKE_GEMINI = "AIzaFakeGeminiKey_1234567890abcd"
ADMIN_PW = "very-strong-pass-1"


def make_app(**over):
    cfg = {"SECRET_KEY": "s" * 40, "ENCRYPTION_KEY": Fernet.generate_key().decode(),
           "ADMIN_USERNAME": "boss", "ADMIN_PASSWORD": ADMIN_PW,
           "STORE": MemoryStore(), "BASE_URL": ""}
    cfg.update(over)
    return create_app(cfg)


class Base(unittest.TestCase):
    def setUp(self):
        self.app = make_app()
        self.store = self.app.store
        self.p = patch("app.validate_page_token",
                       side_effect=lambda pid, tok, ver: (True, f"Page {pid}", None))
        self.meta = self.p.start()

    def tearDown(self):
        self.p.stop()

    def fresh(self):
        c = self.app.test_client()
        c.get("/login")
        return c

    def tok(self, c):
        with c.session_transaction() as s:
            return s["_csrf"]

    def post(self, c, url, data=None, **kw):
        d = dict(data or {})
        d["csrf_token"] = self.tok(c)
        return c.post(url, data=d, **kw)

    def login(self, ident, pw):
        c = self.fresh()
        return c, self.post(c, "/login", {"identifier": ident, "password": pw})

    def admin(self):
        c, r = self.login("boss", ADMIN_PW)
        self.assertEqual(r.status_code, 302)
        return c

    def add_client(self, admin, name="দোকান ১", page_id="100000001", **extra):
        d = {"name": name, "page_id": page_id, "page_token": FAKE_TOKEN, "order_mode": "ai_orders",
             "phone": "", "custom_instructions": "", "gemini_key": ""}
        d.update(extra)
        return self.post(admin, "/admin/clients/new", d)

    def cid(self, page_id):
        return self.store.get("pages", page_id)["client_id"]

    def add_staff(self, admin, email="a@x.com", pw="staffpass1", name="কর্মী", clients=()):
        return self.post(admin, "/admin/staff/new",
                         {"name": name, "email": email, "password": pw, "clients": list(clients)})


class ConfigTests(unittest.TestCase):
    def test_bad_config_stops_app(self):
        with self.assertRaises(RuntimeError) as cm:
            create_app({"SECRET_KEY": "", "ENCRYPTION_KEY": "", "ADMIN_USERNAME": "", "ADMIN_PASSWORD": "",
                        "FIREBASE_SERVICE_ACCOUNT_JSON": "", "ALLOW_MEMORY_STORE": ""})
        m = str(cm.exception)
        for word in ("SECRET_KEY", "ENCRYPTION_KEY", "ADMIN_USERNAME", "ADMIN_PASSWORD", "FIREBASE"):
            self.assertIn(word, m)

    def test_wrong_encryption_key_rejected(self):
        with self.assertRaises(RuntimeError):
            make_app(ENCRYPTION_KEY="not-a-valid-fernet-key")

    def test_memory_store_needs_explicit_permission(self):
        with self.assertRaises(RuntimeError):
            create_app({"SECRET_KEY": "s" * 40, "ENCRYPTION_KEY": Fernet.generate_key().decode(),
                        "ADMIN_USERNAME": "boss", "ADMIN_PASSWORD": ADMIN_PW,
                        "FIREBASE_SERVICE_ACCOUNT_JSON": "", "ALLOW_MEMORY_STORE": ""})


class AuthTests(Base):
    def test_dashboard_needs_login(self):
        r = self.app.test_client().get("/dashboard")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.headers["Location"])

    def test_post_without_csrf_rejected(self):
        c = self.fresh()
        r = c.post("/login", data={"identifier": "boss", "password": ADMIN_PW})
        self.assertEqual(r.status_code, 400)

    def test_post_without_any_session_rejected(self):
        r = self.app.test_client().post("/login", data={"identifier": "boss", "password": ADMIN_PW})
        self.assertEqual(r.status_code, 400)

    def test_admin_login(self):
        _, bad = self.login("boss", "wrong-password-1")
        self.assertEqual(bad.status_code, 401)
        c = self.admin()
        self.assertEqual(c.get("/dashboard").status_code, 200)

    def test_login_rate_limit(self):
        c = self.fresh()
        for _ in range(5):
            self.assertEqual(self.post(c, "/login", {"identifier": "boss", "password": "x" * 12}).status_code, 401)
        self.assertEqual(self.post(c, "/login", {"identifier": "boss", "password": ADMIN_PW}).status_code, 429)

    def test_logout_ends_session(self):
        c = self.admin()
        self.post(c, "/logout")
        self.assertEqual(c.get("/dashboard").status_code, 302)


class StaffTests(Base):
    def test_create_staff_and_login(self):
        a = self.admin()
        self.add_staff(a)
        doc = [s for s in self.store.list("staff")][0]
        self.assertNotEqual(doc["password_hash"], "staffpass1")
        c, r = self.login("A@X.com", "staffpass1")
        self.assertEqual(r.status_code, 302)
        self.assertEqual(c.get("/dashboard").status_code, 200)
        _, bad = self.login("a@x.com", "wrongpass12")
        self.assertEqual(bad.status_code, 401)

    def test_duplicate_email_rejected(self):
        a = self.admin()
        self.add_staff(a)
        self.add_staff(a, name="অন্যজন")
        self.assertEqual(len(self.store.list("staff")), 1)

    def test_short_password_rejected(self):
        a = self.admin()
        self.add_staff(a, pw="short")
        self.assertEqual(len(self.store.list("staff")), 0)

    def test_staff_cannot_use_admin_pages(self):
        a = self.admin()
        self.add_staff(a)
        s, _ = self.login("a@x.com", "staffpass1")
        for url in ("/admin/staff", "/admin/staff/new", "/admin/clients/new", "/admin/audit"):
            self.assertEqual(s.get(url).status_code, 403, url)
        self.assertEqual(self.post(s, "/admin/staff/new", {"name": "x", "email": "b@x.com", "password": "12345678"}).status_code, 403)

    def test_deactivated_staff_loses_access_immediately(self):
        a = self.admin()
        self.add_staff(a)
        s, _ = self.login("a@x.com", "staffpass1")
        sid = self.store.list("staff")[0]["id"]
        self.post(a, f"/admin/staff/{sid}", {"name": "কর্মী"})  # 'active' টিক নেই = বন্ধ
        self.assertEqual(s.get("/dashboard").status_code, 302)
        _, r = self.login("a@x.com", "staffpass1")
        self.assertEqual(r.status_code, 401)


class ClientTests(Base):
    def test_one_page_one_client(self):
        a = self.admin()
        self.add_client(a)
        self.add_client(a, name="দোকান ২")
        self.assertEqual(len(self.store.list("clients")), 1)

    def test_meta_rejection_creates_nothing(self):
        self.meta.side_effect = lambda *x: (False, None, "টোকেন ভুল")
        a = self.admin()
        self.add_client(a)
        self.assertEqual(self.store.list("clients"), [])
        self.assertEqual(self.store.list("pages"), [])

    def test_failed_client_creation_releases_page(self):
        a = self.admin()
        real = self.store.create

        def flaky(coll, doc_id, data):
            if coll == "clients":
                raise RuntimeError("boom")
            return real(coll, doc_id, data)

        with patch.object(self.store, "create", side_effect=flaky):
            r = self.add_client(a)
        self.assertEqual(r.status_code, 500)
        self.assertEqual(self.store.list("pages"), [])

    def test_secrets_encrypted_and_never_shown(self):
        a = self.admin()
        self.add_client(a, gemini_key=FAKE_GEMINI)
        cid = self.cid("100000001")
        doc = self.store.get("clients", cid)
        self.assertNotIn(FAKE_TOKEN, str(doc))
        self.assertNotIn(FAKE_GEMINI, str(doc))
        self.assertEqual(self.app.crypto.decrypt(doc["page_token_enc"]), FAKE_TOKEN)
        self.assertEqual(self.app.crypto.decrypt(doc["gemini_key_enc"]), FAKE_GEMINI)
        self.add_staff(a, clients=[cid])
        s, _ = self.login("a@x.com", "staffpass1")
        for c in (a, s):
            for url in ("/dashboard", "/clients", f"/clients/{cid}", f"/clients/{cid}/settings"):
                body = c.get(url).get_data(as_text=True)
                self.assertNotIn(FAKE_TOKEN, body, url)
                self.assertNotIn(FAKE_GEMINI, body, url)
        self.assertNotIn(FAKE_TOKEN, a.get(f"/admin/clients/{cid}/page").get_data(as_text=True))
        for log in self.store.list("audit_logs"):
            self.assertNotIn(FAKE_TOKEN, str(log))
            self.assertNotIn(FAKE_GEMINI, str(log))

    def test_phone_only_needs_phone(self):
        a = self.admin()
        self.add_client(a, order_mode="phone_only", phone="")
        self.assertEqual(self.store.list("clients"), [])
        self.add_client(a, order_mode="phone_only", phone="01700-000000")
        self.assertEqual(self.store.list("clients")[0]["order_mode"], "phone_only")

    def test_bad_inputs_rejected(self):
        a = self.admin()
        self.add_client(a, page_id="abc")
        self.add_client(a, order_mode="hack")
        self.add_client(a, gemini_key="short key!")
        self.assertEqual(self.store.list("clients"), [])

    def test_staff_sees_only_assigned_clients(self):
        a = self.admin()
        self.add_client(a, name="প্রথম", page_id="100000001")
        self.add_client(a, name="দ্বিতীয়", page_id="100000002")
        c1, c2 = self.cid("100000001"), self.cid("100000002")
        self.add_staff(a, clients=[c1])
        s, _ = self.login("a@x.com", "staffpass1")
        self.assertEqual(s.get(f"/clients/{c1}").status_code, 200)
        self.assertEqual(s.get(f"/clients/{c2}").status_code, 404)
        self.assertEqual(s.get(f"/clients/{c2}/settings").status_code, 404)
        self.assertEqual(self.post(s, f"/clients/{c2}/settings", {"order_mode": "ai_orders"}).status_code, 404)
        body = s.get("/clients").get_data(as_text=True)
        self.assertIn("প্রথম", body)
        self.assertNotIn("দ্বিতীয়", body)

    def test_staff_cannot_touch_admin_only_fields(self):
        a = self.admin()
        self.add_client(a)
        cid = self.cid("100000001")
        self.add_staff(a, clients=[cid])
        s, _ = self.login("a@x.com", "staffpass1")
        self.post(s, f"/clients/{cid}/settings", {"order_mode": "phone_only", "phone": "01700000000",
                  "custom_instructions": "নতুন নির্দেশ", "name": "হ্যাক", "gemini_key": FAKE_GEMINI})
        doc = self.store.get("clients", cid)
        self.assertEqual(doc["order_mode"], "phone_only")
        self.assertEqual(doc["custom_instructions"], "নতুন নির্দেশ")
        self.assertEqual(doc["name"], "দোকান ১")
        self.assertEqual(doc["gemini_key_enc"], "")
        self.assertEqual(self.post(s, f"/admin/clients/{cid}/status", {"to": "suspended"}).status_code, 403)

    def test_suspended_client_hidden_from_staff_but_data_kept(self):
        a = self.admin()
        self.add_client(a)
        cid = self.cid("100000001")
        self.add_staff(a, clients=[cid])
        s, _ = self.login("a@x.com", "staffpass1")
        self.post(a, f"/admin/clients/{cid}/status", {"to": "suspended"})
        self.assertEqual(s.get(f"/clients/{cid}").status_code, 404)
        self.assertEqual(self.store.get("clients", cid)["status"], "suspended")
        self.post(a, f"/admin/clients/{cid}/status", {"to": "active"})
        self.assertEqual(s.get(f"/clients/{cid}").status_code, 200)

    def test_replace_page_rules(self):
        a = self.admin()
        self.add_client(a, name="এক", page_id="100000001")
        self.add_client(a, name="দুই", page_id="100000002")
        c1 = self.cid("100000001")
        url = f"/admin/clients/{c1}/page"
        # নিশ্চিত না করলে Page বদলায় না
        self.post(a, url, {"page_id": "100000003", "page_token": FAKE_TOKEN})
        self.assertEqual(self.store.get("clients", c1)["page_id"], "100000001")
        # অন্য client-এর Page নেওয়া যায় না
        self.post(a, url, {"page_id": "100000002", "page_token": FAKE_TOKEN, "confirm": "on"})
        self.assertEqual(self.store.get("clients", c1)["page_id"], "100000001")
        # সঠিক বদল: পুরনো Page মুক্ত হয়, নতুন দখল হয়
        self.post(a, url, {"page_id": "100000003", "page_token": FAKE_TOKEN, "confirm": "on"})
        self.assertEqual(self.store.get("clients", c1)["page_id"], "100000003")
        self.assertIsNone(self.store.get("pages", "100000001"))
        self.assertEqual(self.store.get("pages", "100000003")["client_id"], c1)
        self.assertTrue(any(l["action"] == "page_replaced" for l in self.store.list("audit_logs")))
        # শুধু টোকেন নবায়ন: নিশ্চিতকরণ লাগে না
        self.post(a, url, {"page_id": "100000003", "page_token": FAKE_TOKEN})
        self.assertTrue(any(l["action"] == "page_token_renewed" for l in self.store.list("audit_logs")))

    def test_replace_page_with_bad_token_changes_nothing(self):
        a = self.admin()
        self.add_client(a)
        c1 = self.cid("100000001")
        self.meta.side_effect = lambda *x: (False, None, "টোকেন ভুল")
        self.post(a, f"/admin/clients/{c1}/page", {"page_id": "100000009", "page_token": FAKE_TOKEN, "confirm": "on"})
        self.assertEqual(self.store.get("clients", c1)["page_id"], "100000001")
        self.assertIsNone(self.store.get("pages", "100000009"))


class PageRenderTests(Base):
    """প্রতিটি পাতা সত্যিই খোলে কি না, ভুলের অবস্থায়ও।"""

    def test_every_page_renders(self):
        a = self.admin()
        self.add_client(a)
        cid = self.cid("100000001")
        self.add_staff(a, clients=[cid])
        sid = self.store.list("staff")[0]["id"]
        for url in ("/dashboard", "/clients", f"/clients/{cid}", f"/clients/{cid}/settings",
                    "/admin/staff", "/admin/staff/new", f"/admin/staff/{sid}", "/admin/clients/new",
                    f"/admin/clients/{cid}/page", "/admin/audit"):
            self.assertEqual(a.get(url).status_code, 200, url)
        s, _ = self.login("a@x.com", "staffpass1")
        for url in ("/dashboard", "/clients", f"/clients/{cid}", f"/clients/{cid}/settings"):
            self.assertEqual(s.get(url).status_code, 200, url)

    def test_error_paths_render_with_messages(self):
        a = self.admin()
        r = self.add_staff(a, pw="short")
        self.assertEqual(r.status_code, 200)
        self.assertIn("৮ অক্ষর", r.get_data(as_text=True))
        r = self.add_client(a, page_id="abc")
        self.assertEqual(r.status_code, 200)
        self.assertIn("সংখ্যা", r.get_data(as_text=True))
        self.add_client(a)
        r = self.add_client(a, name="দুই")
        self.assertEqual(r.status_code, 200)
        self.assertIn("আরেকটি client-এ যুক্ত", r.get_data(as_text=True))
        cid = self.cid("100000001")
        r = self.post(a, f"/clients/{cid}/settings", {"order_mode": "phone_only", "phone": "", "name": "দোকান ১"})
        self.assertEqual(r.status_code, 200)
        self.assertIn("ফোন নম্বর দিতে হবে", r.get_data(as_text=True))
        sid_doc = self.add_staff(a)
        sid = self.store.list("staff")[0]["id"]
        r = self.post(a, f"/admin/staff/{sid}", {"name": "", "password": "x"})
        self.assertEqual(r.status_code, 200)

    def test_staff_edit_keeps_assignments_and_active(self):
        a = self.admin()
        self.add_client(a)
        cid = self.cid("100000001")
        self.add_staff(a, clients=[cid])
        sid = self.store.list("staff")[0]["id"]
        body = a.get(f"/admin/staff/{sid}").get_data(as_text=True)
        self.assertEqual(body.count("checked"), 2)  # সক্রিয় + একটি client
        self.post(a, f"/admin/staff/{sid}", {"name": "নতুন নাম", "active": "on", "clients": [cid]})
        doc = self.store.get("staff", sid)
        self.assertEqual((doc["name"], doc["active"], doc["assigned_client_ids"]), ("নতুন নাম", True, [cid]))


class MiscTests(Base):
    def test_health_shows_no_secrets(self):
        body = self.app.test_client().get("/health").get_data(as_text=True)
        self.assertIn("memory", body)
        self.assertNotIn(ADMIN_PW, body)

    def test_security_headers(self):
        r = self.app.test_client().get("/login")
        self.assertEqual(r.headers["X-Frame-Options"], "DENY")
        self.assertIn("default-src 'self'", r.headers["Content-Security-Policy"])

    def test_html_is_escaped(self):
        a = self.admin()
        self.add_client(a, name="<script>alert(1)</script>")
        body = a.get("/clients").get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", body)

    def test_unknown_client_is_404(self):
        a = self.admin()
        self.assertEqual(a.get("/clients/doesnotexist").status_code, 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)
