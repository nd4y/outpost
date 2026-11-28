package filekit

import "context"

// Verification contains only opaque identities and counts. Decrypted names,
// attributes, chunk hashes and keys must not escape the trusted verifier.
type Verification struct {
	File    string `json:"file"`
	Version string `json:"version"`
	Kind    string `json:"kind"`
	Bytes   int64  `json:"bytes"`
}

// VerifyRecoveryKit authenticates metadata, decrypts every selected chunk and
// checks the ordered plaintext digest without creating a plaintext file. It
// does not certify that a target filesystem can restore the recorded attributes.
func VerifyRecoveryKit(ctx context.Context, owner Owner, kit RecoveryKit, read ObjectReader) (Verification, error) {
	var result Verification
	if e := ctx.Err(); e != nil {
		return result, e
	}
	if owner.validate() != nil || read == nil {
		return result, ErrInvalid
	}
	s := &Store{Owner: owner, backend: readOnlyBackend{read: read}}
	_, d, e := s.loadEnvelope(ctx, kit.Root, kit.Version)
	if e != nil {
		return result, e
	}
	if e = s.verifyDescriptor(ctx, d); e != nil {
		return result, e
	}
	kind := d.Kind
	if kind == "" {
		kind = "file"
	}
	return Verification{File: d.File, Version: kit.Version, Kind: kind, Bytes: d.Size}, nil
}
