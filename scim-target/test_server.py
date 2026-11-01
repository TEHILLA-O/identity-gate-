import sys
from pathlib import Path

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent))
from server import create_app  # noqa: E402


def test_directory_supports_the_documented_scim_subset():
    app = create_app("sqlite+pysqlite:///:memory:", token="directory-token")
    client = TestClient(app)
    denied = client.get("/scim/v2/Users")
    assert denied.status_code == 401
    headers = {"Authorization": "Bearer directory-token"}
    created = client.post("/scim/v2/Users", headers=headers, json={"schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"], "userName": "ada.north", "externalId": "NS-1", "active": True, "name": {"givenName": "Ada", "familyName": "North"}})
    assert created.status_code == 201
    user_id = created.json()["id"]
    duplicate = client.post("/scim/v2/Users", headers=headers, json={"userName": "ada.north", "externalId": "NS-1", "active": True})
    assert duplicate.status_code == 409
    filtered = client.get('/scim/v2/Users?filter=externalId eq "NS-1"', headers=headers)
    assert filtered.json()["totalResults"] == 1
    patched = client.patch(f"/scim/v2/Users/{user_id}", headers=headers, json={"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "replace", "path": "active", "value": False}]})
    assert patched.json()["active"] is False
    group = client.post("/scim/v2/Groups", headers=headers, json={"schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"], "displayName": "finance"})
    assert group.status_code == 201
    group_id = group.json()["id"]
    added = client.patch(f"/scim/v2/Groups/{group_id}", headers=headers, json={"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "add", "path": "members", "value": user_id}]})
    assert any(member["value"] == user_id for member in added.json()["members"])
    listed = client.get(f'/scim/v2/Groups?filter=members.value eq "{user_id}"', headers=headers)
    assert listed.json()["totalResults"] == 1
    removed = client.patch(f"/scim/v2/Groups/{group_id}", headers=headers, json={"schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"], "Operations": [{"op": "remove", "path": f'members[value eq "{user_id}"]'}]})
    assert removed.json()["members"] == []
    assert client.delete(f"/scim/v2/Users/{user_id}", headers=headers).status_code == 204
