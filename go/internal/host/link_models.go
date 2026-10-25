package host

import (
	"encoding/json"

	"github.com/peerspan/peerspan/go/internal/linking"
)

type LinkRequestView struct {
	RequestID         string   `json:"request_id"`
	Mode              string   `json:"mode"`
	State             string   `json:"state"`
	NetworkID         string   `json:"network_id"`
	PersonID          string   `json:"person_id"`
	HostID            string   `json:"host_id"`
	DeviceFingerprint string   `json:"device_fingerprint"`
	ExpiresAt         string   `json:"expires_at"`
	Completed         []string `json:"completed"`
	Attention         []string `json:"attention"`
	Next              []string `json:"next"`
}
type LinkRequestResult struct {
	LinkRequestView
	DisplayCode string `json:"display_code,omitempty"`
}
type LinkSigningRequest struct {
	ObjectType      string `json:"object_type"`
	MessageBase64   string `json:"message_base64"`
	SignerPublicKey string `json:"signer_public_key"`
	SignatureFormat string `json:"signature_format"`
}
type LinkReview struct {
	NetworkID        string `json:"network_id"`
	PersonID         string `json:"person_id"`
	HostPublicKey    string `json:"host_public_key"`
	DevicePublicKey  string `json:"device_public_key"`
	Scopes           uint64 `json:"scopes"`
	NotAfter         string `json:"not_after"`
	SignerPublicKey  string `json:"signer_public_key"`
	AuthorityWarning string `json:"authority_warning"`
}
type LinkApprovalResult struct {
	Request         LinkRequestView      `json:"request"`
	Review          LinkReview           `json:"review"`
	SigningRequests []LinkSigningRequest `json:"signing_requests"`
}
type LinkSelectionReview struct {
	OwnerOfferID        string `json:"owner_offer_id"`
	NetworkID           string `json:"network_id"`
	PersonID            string `json:"person_id"`
	PersonPublicKey     string `json:"person_public_key"`
	HostPublicKey       string `json:"host_public_key"`
	DevicePublicKey     string `json:"device_public_key"`
	CertificateID       string `json:"certificate_id"`
	IssuerCertificateID string `json:"issuer_certificate_id"`
	Scopes              uint64 `json:"scopes"`
	NotAfter            string `json:"not_after"`
	SignerPublicKey     string `json:"signer_public_key"`
	AuthorityWarning    string `json:"authority_warning"`
}
type LinkCommitReview struct {
	LinkSelectionReview
	SelectionID                  string `json:"selection_id"`
	AdministratorOfferID         string `json:"administrator_offer_id"`
	AdmissionRecordID            string `json:"admission_record_id"`
	AdmissionRecordBase64        string `json:"admission_record_base64"`
	AdministratorSignerPublicKey string `json:"administrator_signer_public_key"`
}
type LinkSelectionResult struct {
	Request LinkRequestView     `json:"request"`
	Review  LinkSelectionReview `json:"review"`
}
type LinkCommitResult struct {
	Request LinkRequestView  `json:"request"`
	Review  LinkCommitReview `json:"review"`
}
type CreateLinkRequest struct {
	Mode                 string `json:"mode"`
	NetworkID            string `json:"network_id"`
	PersonPublicKey      string `json:"person_public_key"`
	CoordinatorAddress   string `json:"coordinator_address"`
	CoordinatorPublicKey string `json:"coordinator_public_key"`
}
type ApproveLink struct {
	Code              string `json:"code"`
	NetworkID         string `json:"network_id"`
	ExpectedPersonID  string `json:"expected_person_id"`
	ExpectedHostKey   string `json:"expected_host_key"`
	ExpectedDeviceKey string `json:"expected_device_key"`
	Signer            string `json:"signer"`
	Approve           bool   `json:"approve"`
}
type SelectLink struct {
	OwnerOfferID    string `json:"owner_offer_id"`
	NetworkID       string `json:"network_id"`
	PersonPublicKey string `json:"person_public_key"`
	HostPublicKey   string `json:"host_public_key"`
	DevicePublicKey string `json:"device_public_key"`
	Approve         bool   `json:"approve"`
}
type CommitLink struct {
	OwnerOfferID         string `json:"owner_offer_id"`
	SelectionID          string `json:"selection_id"`
	AdministratorOfferID string `json:"administrator_offer_id"`
	NetworkID            string `json:"network_id"`
	PersonPublicKey      string `json:"person_public_key"`
	HostPublicKey        string `json:"host_public_key"`
	DevicePublicKey      string `json:"device_public_key"`
	Approve              bool   `json:"approve"`
}
type linkSignature struct {
	ObjectType string `json:"object_type"`
	Signature  string `json:"signature"`
}

func (s *linkSignature) UnmarshalJSON(raw []byte) error {
	type plain linkSignature
	return linking.DecodeStoredJSON(raw, "object_type signature", (*plain)(s))
}

type linkIntent struct {
	Format                    uint64          `json:"format"`
	Approved                  bool            `json:"approved"`
	Epoch                     uint64          `json:"epoch"`
	FeatureID                 string          `json:"feature_id"`
	PersonPublicKey           string          `json:"person_public_key"`
	CertificateID             string          `json:"certificate_id"`
	SignerPublicKey           string          `json:"signer_public_key"`
	Scopes                    uint64          `json:"scopes"`
	IssuedAt                  string          `json:"issued_at"`
	NotAfter                  string          `json:"not_after"`
	CertificateTemplateBase64 string          `json:"certificate_template_base64"`
	RecordTemplateBase64      string          `json:"record_template_base64"`
	PacketTemplateBase64      string          `json:"packet_template_base64"`
	Signatures                []linkSignature `json:"signatures"`
}

const linkIntentFields = "format approved epoch feature_id person_public_key certificate_id signer_public_key scopes issued_at not_after certificate_template_base64 record_template_base64 packet_template_base64 signatures"

type linkIntentValue struct{ Intent *linkIntent }

func (v linkIntentValue) MarshalJSON() ([]byte, error) {
	if v.Intent == nil {
		return []byte(`"-"`), nil
	}
	return json.Marshal(v.Intent)
}
func (v *linkIntentValue) UnmarshalJSON(raw []byte) error {
	var absent string
	if json.Unmarshal(raw, &absent) == nil && absent == "-" {
		v.Intent = nil
		return nil
	}
	var i linkIntent
	if e := linking.DecodeStoredJSON(raw, linkIntentFields, &i); e != nil {
		return e
	}
	if i.Format != 1 || i.Signatures == nil {
		return linkFail("state_conflict", "-", "storage")
	}
	v.Intent = &i
	return nil
}

type linkOutboundFrame struct {
	Role            string `json:"role"`
	WriterPublicKey string `json:"writer_public_key"`
	FrameID         string `json:"frame_id"`
	Published       bool   `json:"published"`
	Sequence        uint64 `json:"sequence"`
}

func (f *linkOutboundFrame) UnmarshalJSON(raw []byte) error {
	type plain linkOutboundFrame
	return linking.DecodeStoredJSON(raw, "role writer_public_key frame_id published sequence", (*plain)(f))
}

type linkRecord struct {
	Format                    uint64              `json:"format"`
	NetworkBase64             string              `json:"network_base64"`
	ExpectedNetworkID         string              `json:"expected_network_id"`
	ExpectedPersonPublicKey   string              `json:"expected_person_public_key"`
	CoordinatorAddress        string              `json:"coordinator_address"`
	CoordinatorPublicKey      string              `json:"coordinator_public_key"`
	HostPublicKey             string              `json:"host_public_key"`
	DevicePublicKey           string              `json:"device_public_key"`
	RequestNonce              string              `json:"request_nonce"`
	RequestPacketBase64       string              `json:"request_packet_base64"`
	OwnerPacketBase64         string              `json:"owner_packet_base64"`
	SelectionPacketBase64     string              `json:"selection_packet_base64"`
	AdministratorPacketBase64 string              `json:"administrator_packet_base64"`
	CommitPacketBase64        string              `json:"commit_packet_base64"`
	ResultPacketBase64        string              `json:"result_packet_base64"`
	CatalogBase64             string              `json:"catalog_base64"`
	OwnerOfferID              string              `json:"owner_offer_id"`
	SelectionID               string              `json:"selection_id"`
	AdministratorOfferID      string              `json:"administrator_offer_id"`
	ManifestID                string              `json:"manifest_id"`
	AfterSequence             uint64              `json:"after_sequence"`
	SelectionApproved         bool                `json:"selection_approved"`
	CommitApproved            bool                `json:"commit_approved"`
	OwnerIntent               linkIntentValue     `json:"owner_intent"`
	AdministratorIntent       linkIntentValue     `json:"administrator_intent"`
	OutboundFrames            []linkOutboundFrame `json:"outbound_frames"`
}

const linkRecordFields = "format network_base64 expected_network_id expected_person_public_key coordinator_address coordinator_public_key host_public_key device_public_key request_nonce request_packet_base64 owner_packet_base64 selection_packet_base64 administrator_packet_base64 commit_packet_base64 result_packet_base64 catalog_base64 owner_offer_id selection_id administrator_offer_id manifest_id after_sequence selection_approved commit_approved owner_intent administrator_intent outbound_frames"

func emptyLinkRecord() linkRecord {
	return linkRecord{Format: 1, NetworkBase64: "-", ExpectedNetworkID: "-", ExpectedPersonPublicKey: "-", CoordinatorAddress: "-", CoordinatorPublicKey: "-", HostPublicKey: "-", DevicePublicKey: "-", RequestNonce: "-", RequestPacketBase64: "-", OwnerPacketBase64: "-", SelectionPacketBase64: "-", AdministratorPacketBase64: "-", CommitPacketBase64: "-", ResultPacketBase64: "-", CatalogBase64: "-", OwnerOfferID: "-", SelectionID: "-", AdministratorOfferID: "-", ManifestID: "-", OutboundFrames: []linkOutboundFrame{}}
}
func decodeLinkRecord(raw []byte) (linkRecord, error) {
	var r linkRecord
	if e := linking.DecodeStoredJSON(raw, linkRecordFields, &r); e != nil {
		return r, e
	}
	if r.Format != 1 || r.OutboundFrames == nil {
		return r, linkFail("state_conflict", "-", "storage")
	}
	return r, nil
}
