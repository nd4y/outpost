package main

import (
	"context"
	"crypto/ed25519"

	"github.com/nd4y/outpost/internal/recoverybundle"
	"github.com/nd4y/outpost/internal/worker"
)

func createOwnerEpoch(ctx context.Context, profileFile, authorityFile, output string) (recoverybundle.EpochPreparation, error) {
	var result recoverybundle.EpochPreparation
	raw, err := worker.ReadPrivate(profileFile, recoverybundle.MaxEpochDocument)
	if err != nil {
		return result, err
	}
	var profile recoverybundle.EpochProfile
	if worker.DecodeInput(raw, &profile, recoverybundle.MaxEpochDocument) != nil {
		return result, errUsage
	}
	raw, err = worker.ReadPrivate(authorityFile, 4096)
	if err != nil {
		return result, err
	}
	var key struct {
		PrivateKey ed25519.PrivateKey `json:"privateKey"`
	}
	if worker.DecodeInput(raw, &key, 4096) != nil {
		return result, errUsage
	}
	return recoverybundle.PrepareEpoch(ctx, profile, key.PrivateKey, output)
}

func inspectOwnerEpoch(receiptFile, ownerFile string) (recoverybundle.EpochPreparation, error) {
	var result recoverybundle.EpochPreparation
	raw, err := worker.ReadPrivate(ownerFile, 4096)
	if err != nil {
		return result, err
	}
	var trust struct {
		PublicKey ed25519.PublicKey `json:"publicKey"`
	}
	if worker.DecodeInput(raw, &trust, 4096) != nil {
		return result, errUsage
	}
	raw, err = worker.ReadPrivate(receiptFile, recoverybundle.MaxEpochDocument)
	if err != nil {
		return result, err
	}
	return recoverybundle.VerifyEpochPreparation(raw, trust.PublicKey)
}
