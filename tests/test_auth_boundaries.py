"""Additional fail-closed provider boundary tests; no external services."""
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from bifrost_budget.auth import AuthenticationError, TokenVerifier
from bifrost_budget.server import _validated_identity
from bifrost_budget.settings import BifrostSettings

ISSUER = "https://identity.example.test"
TENANT = "11111111-1111-4111-8111-111111111111"
OID = "33333333-3333-4333-8333-333333333333"


@pytest.mark.asyncio
@pytest.mark.parametrize("algorithm", ["none", "HS256"])
async def test_algorithm_confusion_rejected_without_key_requests(algorithm):
    token = jwt.encode({"sub": "fake"}, "" if algorithm == "none" else "synthetic-secret-with-at-least-32-bytes", algorithm=algorithm, headers={"kid": "test"})
    def unexpected(request):
        pytest.fail("Rejected algorithm must not make a key request")
    async with httpx.AsyncClient(transport=httpx.MockTransport(unexpected)) as client:
        verifier = TokenVerifier(issuer=ISSUER, audience="api", discovery_url=ISSUER+"/metadata", jwks_url=ISSUER+"/keys", client=client)
        with pytest.raises(AuthenticationError):
            await verifier.verify("Bearer " + token)


@pytest.mark.parametrize("missing", ["tid", "oid", "scp", "ver"])
def test_missing_entra_identity_or_flow_claim_denied(missing):
    claims = {"tid": TENANT, "oid": OID, "scp": "Quota.Read", "ver": "2.0"}
    del claims[missing]
    settings = BifrostSettings(api_base_url="https://bifrost.example.test", entra_tenant_id=TENANT, auth_scope="Quota.Read", entra_user_map={f"{TENANT}:{OID}": "user-7"})
    with pytest.raises(AuthenticationError):
        _validated_identity(claims, settings)


def test_unmapped_entra_user_and_ping_application_are_denied():
    settings = BifrostSettings(api_base_url="https://bifrost.example.test", entra_tenant_id=TENANT, auth_scope="Quota.Read", entra_user_map={})
    with pytest.raises(AuthenticationError, match="user_mapping_missing"):
        _validated_identity({"tid": TENANT, "oid": OID, "scp": "Quota.Read", "ver": "2.0"}, settings)
    ping = BifrostSettings(api_base_url="https://bifrost.example.test", auth_provider="ping", auth_scope="quota.read")
    with pytest.raises(AuthenticationError, match="app_only_unsupported"):
        _validated_identity({"idtyp": "app", "scope": "quota.read", "displayname": "Human-looking Name"}, ping)


@pytest.mark.asyncio
async def test_metadata_mismatch_never_fetches_untrusted_keys():
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    token = jwt.encode({"iss": ISSUER, "aud": "api", "sub": "user", "nbf": int(time.time())-1, "exp": int(time.time())+300}, private, algorithm="RS256", headers={"kid": "test"})
    calls = []
    def metadata(request):
        calls.append(str(request.url))
        return httpx.Response(200, json={"issuer": ISSUER, "jwks_uri": "https://attacker.example.test/keys"})
    async with httpx.AsyncClient(transport=httpx.MockTransport(metadata)) as client:
        verifier = TokenVerifier(issuer=ISSUER, audience="api", discovery_url=ISSUER+"/metadata", jwks_url=ISSUER+"/keys", client=client)
        with pytest.raises(AuthenticationError, match="key_service_unavailable"):
            await verifier.verify("Bearer " + token)
    assert calls == [ISSUER+"/metadata"]