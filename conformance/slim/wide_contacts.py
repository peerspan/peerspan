#!/usr/bin/env python3
"""Slim suite, wide contacts: hosts whose contacts name 8 first-contact addresses link and join (DEC-Q34).

Written from docs/decentralized-spec.md sections 8 (Limits) and 20 (item 30), the wire appendix
(docs/decentralized-wire-formats.md sections 8.1, 8.2 and 10.1), the carrier_endpoints paragraph of
docs/decentralized-storage-contract.md, the transport configuration file of docs/decentralized-runtime-contract.md
and DEC-Q34 in docs/decision-log.md only.
"""
import base64
import json

from harness import (Failure, Suite, b64url_json, check, create_network, invite, join_new_person, link_machine,
                     link_view, members, ssh_key)

suite = Suite("wide_contacts", __doc__)


def eight_address_host(name):
    """A fresh host whose contacts name 8 first-contact addresses: its real bootstrap listener and 7 unused
    loopback hints (127.0.0.2 to 127.0.0.8, where nothing listens), sorted by ASCII (appendix 8.1, 8.2)."""
    h = suite.host(name, start=False)
    addresses = [f"127.0.0.{n}:{h.bootstrap_port}" for n in range(1, 9)]
    config = h.root / "transport.json"
    config.write_text(json.dumps({"format": 1, "advertise_bootstrap": addresses, "advertise_quic": [h.peer_address],
                                  "rendezvous": [], "relays": [], "publish_contacts": False},
                                 separators=(",", ":")))
    config.chmod(0o600)
    h.extra_args = ["--transport-config", config]
    h.addresses = addresses
    return h.start()


@suite.case("eight_address_contacts_link_and_join", "spec 8 Limits, 20 item 30 (DEC-Q34)")
def _():
    owner, machine, joiner = (eight_address_host(n) for n in ("wide-owner", "wide-machine", "wide-joiner"))
    net = create_network(owner, "wide-contacts", "wendy")
    network, person = net["id"], net["person_public_key"]
    # The precondition: the owner's signed contact names all 8 bootstrap addresses.
    code = b64url_json(invite(owner, "probe", network)["invitation"], "psi2-")
    contacts = json.loads(base64.b64decode(code["payload_base64"]))["contacts"]
    named = [json.loads(base64.b64decode(c["payload_base64"]))["bootstrap_addresses"] for c in contacts]
    check(owner.addresses in named, f"the owner's contacts name bootstrap addresses {named}, want {owner.addresses}")
    step = "link a second machine"
    try:
        rid = link_machine(owner, machine, network, person, key=owner.home / ".config/peerspan/person_ed25519")
        check(link_view(machine, rid)["state"] == "linked", f"link request {rid} is not linked")
        step = "join a new person"
        rid = join_new_person(owner, joiner, "xavier", ssh_key(joiner.root, "xavier"), network)
        check(link_view(owner, rid)["state"] == "linked", f"join request {rid} is not linked on the inviter")
    except Failure as error:
        quota = any(text in str(error) for text in ("quota_exceeded", "quota exceeded"))
        refused = " refused with quota_exceeded (DEC-Q34: endpoints past 64 are left out, never refused)" if quota else ""
        raise Failure(f"{step} between hosts with 8-address contacts{refused}: {error}") from None
    on_owner = members(owner, network)
    check(machine.public_key in on_owner and on_owner[machine.public_key]["person_public_key"] == person,
          "the second machine is not bound to the owner's person")
    check(joiner.public_key in on_owner and on_owner[joiner.public_key]["person_public_key"] != person,
          "the new person's host is not a member under its own person")


suite.finish()
