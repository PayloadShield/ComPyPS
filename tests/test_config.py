"""Tests for PayloadShieldEnc.init() key configuration resolution."""

import tempfile
from pathlib import Path

from compyps import PayloadShieldEnc


def test_init_stores_symmetric_key():
    PayloadShieldEnc.init({"Key": "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"})
    assert PayloadShieldEnc.get_config()["Key"] == "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"

def test_init_accepts_raw_key_content():
    PayloadShieldEnc.init({"PrivateKey": """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0TCUqGYggNFKx4Ff3Nk6O7P0nuumoyXFBKtALNIVaqGlBUJ0
0x24PUAo0hzZuK4gFOyMaB8Q6Z3re/cOsKTQs/XtcghNYx0RrhVR+Cb/v6pGNjpK
nK8bYcc87zmM5hhMSaYDhBEwrCIb/xHpY5BPaa0PED4abSdU9tSuAXzLBv/kpMRu
xf7qN30zS8+6M3/m2cN7+B4Qmjv+ipmqpy1AFcvoRjrJWfcElLWRgvKHrPOhKc1N
iAGoAEoq70cYPWXnPvXRi1FoD0a8ppIFznRFJ8h7/qf9GK4sZ3IQ9hTsRYSeZ8ss
tFZMAE/iEl14f+7VfoWjc9XRKKyTDdsiyTV4CwIDAQABAoIBACh6f5GUbX6vwQoY
4T1hdXC/Ejs8Ozr/oH+WSa1Cm61OCRoa8XM2oYOMqjl6JrEjVIbn/QVa2ZFzIvGS
bW/F/LKOCHvT2nGu2tB2RK3BkiR65OoyXmSyR5ikjoh1+Os/UWfA7ZY9I09zrDov
s5s1/f/jYnJQqhlsDndS0TbteHXqbXw9bMsgYaDaOqM3gBVtMyucAKnXobgdUBXw
sh9TcdC0i41J4T4GZrv4KY3UCAVYvCduCmvPzB7Zt1+r5woNanDSFMnkHa1c0WiB
yfsisE5CfvkdGOeNsvRt97cYr2rESRJ/sFHJKXLFGkUcocofQJZFu8h1ABylUOJa
/NDu/UECgYEA1uKLRsOuRh/PJlZZhpQHDBVfkSQLwr8h2iFMxm78c537LuYWmd7z
Xq9LsV06OLlVuIcPcYX5VMkPeVo653EyC9mZK+1jDlJ0x6FSr36a2NSa997IebRF
Dz/zaphBlRex1zqLhrBnDeIYBODxMYVZl7Dwb55uOYiV3d38AgqXicsCgYEA+TcT
rbxsqlNVw3MKo82Nkw6dLpa83zoM7QYD/Ds6Nol4uWtWG2WAkcCTGML78pbIQsRO
+dEdgzeYjuSwfMgyRcGBJxieaLoN/Mkv/Dq9kQFqMXT9W/RACyKHwuY9jbb/zuHl
U3EBMbRY2T4AWZ3F3g5gUmHzO9KRRZcmeZlJAsECgYAtLP9+5xCyaWmRc8HqiyBY
J/4pc1yNmsUxKKMNbLPiUqpGF9VUkAy2MUBGj4T3++7LlolmonXin0qDhravhZqx
5xNOqt+SWT934LCTeJhxUXEq/0lCXOXP6O/xzwSqpYqb5xECRf/EaW4HSIsskA5f
17EUpkgiDFcFh++9NiDZtQKBgQCcDMXQuzTb7nS8fvPBn/uvgq4ftxmrOcFQRb0H
GtsXvTsP98siOouoOIqjLazvuUTKsfu16CBvwsdPapmsePspvMIvhfXjI+WQTTYz
3WBIRTeGonfnNWlIz6VtABi4/Ubu93pOpmsWAZTE61Lyyp1Ur3HXBCh3ZCG9Dqlz
6OzTwQKBgGlXte6m5xNAQHb1J31izGdm60g+Zv6DgQk3SpMHo4zT+LP++7i7xiPJ
YVcxJ98vEaifqOHbYePWqcBjevTrXnt85myIQDT6+Rt55qblwRim2WZgzbAVd4sB
Cz/TEcLzMv6taRKCz58NyOJrpqJxbFuwO2olKO8rJVu7nX1VPcbV
-----END RSA PRIVATE KEY-----"""})
    assert PayloadShieldEnc.get_config()["PrivateKey"].startswith("-----BEGIN RSA PRIVATE KEY-----")


def test_init_accepts_key_file_path():
    with tempfile.TemporaryDirectory() as tmp_dir:
        key_path = Path(tmp_dir) / "public.pem"
        key_path.write_text("""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0TCUqGYggNFKx4Ff3Nk6
O7P0nuumoyXFBKtALNIVaqGlBUJ00x24PUAo0hzZuK4gFOyMaB8Q6Z3re/cOsKTQ
s/XtcghNYx0RrhVR+Cb/v6pGNjpKnK8bYcc87zmM5hhMSaYDhBEwrCIb/xHpY5BP
aa0PED4abSdU9tSuAXzLBv/kpMRuxf7qN30zS8+6M3/m2cN7+B4Qmjv+ipmqpy1A
FcvoRjrJWfcElLWRgvKHrPOhKc1NiAGoAEoq70cYPWXnPvXRi1FoD0a8ppIFznRF
J8h7/qf9GK4sZ3IQ9hTsRYSeZ8sstFZMAE/iEl14f+7VfoWjc9XRKKyTDdsiyTV4
CwIDAQAB
-----END PUBLIC KEY-----""")
        PayloadShieldEnc.init({"PublicKey": str(key_path)})
        assert PayloadShieldEnc.get_config()["PublicKey"] == key_path.read_text()


def test_init_defaults_missing_keys_to_none():
    PayloadShieldEnc.init({})
    config = PayloadShieldEnc.get_config()
    assert config["Key"] is None
    assert config["PrivateKey"] is None
    assert config["PublicKey"] is None
