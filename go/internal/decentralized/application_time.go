package decentralized

// ActivationDeadline is the hard ceiling of the already verified target and
// every applicable packet issuer at first application. The host checks actual
// local decision time against this immediately before its outcome signature;
// expensive pure verification need not finish within one wall-clock second.
func (p *Projection) ActivationDeadline(activation *ParsedActivation) (string, error) {
	if p == nil || p.authority == nil || activation == nil {
		return "", invalid()
	}
	a := p.authority
	target, e := a.graph.get(stringField(activation.Manifest, "device_lease_id"))
	if e != nil {
		return "", e
	}
	path, e := a.evaluate(target)
	if e != nil {
		return "", e
	}
	ceiling := path.After
	for _, packet := range []*Packet{activation.Owner, activation.Administrator} {
		if packet == nil {
			continue
		}
		refs, e := a.graph.packetIssuerRefs(packet)
		if e != nil {
			return "", e
		}
		for _, ref := range refs {
			path, e := a.evaluateFor(ref, target, map[string]bool{})
			if e != nil {
				return "", e
			}
			ceiling = minAfter(ceiling, path.After)
		}
	}
	return ceiling, nil
}
