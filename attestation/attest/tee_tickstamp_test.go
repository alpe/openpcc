// Copyright 2025 Nonvolatile Inc. d/b/a Confident Security
//
// Licensed under the Confident Security Limited License, the
// terms and conditions of which are set forth in the "LICENSE"
// file included in the root directory of this code repository
// (the "License"); you may not use this file except in compliance
// with the License. You may obtain a copy of the License at
//
// license.confident.security/limited/v1
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package attest_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/openpcc/openpcc/attestation/attest"
	"github.com/openpcc/openpcc/attestation/evidence"
	"github.com/openpcc/openpcc/attestation/verify"
	cstpm "github.com/openpcc/openpcc/tpm"

	tpm2 "github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/google/go-tpm/tpmutil"

	"github.com/stretchr/testify/require"
)

func TestVerifyAKSignature_Success(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	public := tpm2.New2B(tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			Restricted:          true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				KeyBits: 2048,
			},
		),
	})

	createSigningCommand := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      public,
	}
	createSigningResponse, err := createSigningCommand.Execute(thetpm)

	if err != nil {
		t.Fatalf("Failed to create primary: %v", err)
	}

	tpmtPublic, err := createSigningResponse.OutPublic.Contents()

	require.NoError(t, err)

	rsaParams, err := tpmtPublic.Parameters.RSADetail()

	require.NoError(t, err)

	n, err := tpmtPublic.Unique.RSA()

	require.NoError(t, err)

	signingPublicKey, err := cstpm.RSAPub(rsaParams, n)

	require.NoError(t, err)

	messageText := []byte{0x0d, 0x0e, 0x0a, 0x0d}

	messageSe := evidence.SignedEvidencePiece{
		Data:      messageText,
		Signature: []byte{},
		Type:      evidence.SevSnpReport,
	}

	attestor := attest.NewTeeTickstampAttestor(
		thetpm,
		tpmutil.Handle(createSigningResponse.ObjectHandle),
		&messageSe,
	)

	se, err := attestor.CreateSignedEvidence(t.Context())

	require.NoError(t, err)

	timeInfo, err := verify.TeeTickstamp(t.Context(), signingPublicKey, se, &messageSe)

	require.NoError(t, err)
	require.GreaterOrEqual(t, int64(timeInfo.Time.ClockInfo.Clock), int64(0))
}

func TestVerifyAKSignature_FailureWrongKey(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	public := tpm2.New2B(tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgRSA,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			SignEncrypt:         true,
			Restricted:          true,
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgRSA,
			&tpm2.TPMSRSAParms{
				Scheme: tpm2.TPMTRSAScheme{
					Scheme: tpm2.TPMAlgRSASSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgRSASSA,
						&tpm2.TPMSSigSchemeRSASSA{
							HashAlg: tpm2.TPMAlgSHA256,
						},
					),
				},
				KeyBits: 2048,
			},
		),
	})

	createSigningCommand := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      public,
	}
	createSigningResponse, err := createSigningCommand.Execute(thetpm)

	if err != nil {
		t.Fatalf("Failed to create primary: %v", err)
	}

	// Create random rsa keypair that will fail verification.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to create pubkey: %v", err)
	}

	messageText := []byte{0x0d, 0x0e, 0x0a, 0x0d}
	messageSe := evidence.SignedEvidencePiece{
		Data:      messageText,
		Signature: []byte{},
		Type:      evidence.TdxReport,
	}

	attestor := attest.NewTeeTickstampAttestor(
		thetpm,
		tpmutil.Handle(createSigningResponse.ObjectHandle),
		&messageSe,
	)

	se, err := attestor.CreateSignedEvidence(t.Context())

	require.NoError(t, err)
	_, err = verify.TeeTickstamp(t.Context(), &privateKey.PublicKey, se, &messageSe)

	require.EqualError(t, err, "crypto/rsa: verification error")
}
