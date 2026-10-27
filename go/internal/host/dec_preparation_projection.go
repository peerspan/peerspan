package host

import dec "github.com/peerspan/peerspan/go/internal/decentralized"

func decPreparationProjection(d dec.Descriptor, prior []byte, catalog *dec.Catalog, p decPending, owner *dec.Packet, now string) (*dec.Projection, error) {
	if p.Record.Selection == "-" || p.Record.OwnerID != owner.ID || p.Record.Administrator == "-" && (p.Record.Mode != "renew" || p.Record.Finalization == "-") {
		return dec.Project(d, prior, catalog.Raw, now, "repair")
	}
	selection, e := dec.ReadPacket(d, mustDecBytes(p.Record.Selection))
	if e != nil {
		return nil, e
	}
	if selection.ID != p.Record.SelectionID {
		return nil, decStorageError()
	}
	var administrator *dec.Packet
	if p.Record.Administrator != "-" {
		administrator, e = dec.ReadPacket(d, mustDecBytes(p.Record.Administrator))
		if e != nil {
			return nil, e
		}
		if administrator.ID != p.Record.AdministratorID {
			return nil, decStorageError()
		}
	} else if p.Record.AdministratorID != "-" {
		return nil, decStorageError()
	}
	var final *dec.Packet
	if p.Record.Finalization != "-" {
		final, e = dec.ReadPacket(d, mustDecBytes(p.Record.Finalization))
		if e != nil {
			return nil, e
		}
		if final.ID != p.Record.FinalizationID {
			return nil, decStorageError()
		}
	}
	return dec.PrepareCeremonyProjection(d, prior, catalog.Raw, p.Request, owner, selection, administrator, final, now)
}
