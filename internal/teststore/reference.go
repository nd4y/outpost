package teststore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// PublicV1Owner reconstructs the deliberately public synthetic recovery data
// for the frozen v1 compatibility fixture. It is never production enrollment.
// No private signing key is included in the returned document.
func PublicV1Owner() []byte {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x37}, ed25519.SeedSize))
	domain := sha256.Sum256([]byte("outpost public regular v1 compatibility fixture"))
	raw, e := json.Marshal(map[string]any{"format": "outpost-filekit-1", "domain": hex.EncodeToString(domain[:]), "master": bytes.Repeat([]byte{0x2a}, 32), "verifyKey": key.Public().(ed25519.PublicKey)})
	if e != nil {
		panic(e)
	}
	return raw
}
