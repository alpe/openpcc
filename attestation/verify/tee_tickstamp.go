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

package verify

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"errors"

	"github.com/google/go-tpm/tpm2"
	"github.com/openpcc/openpcc/attestation/evidence"
)

func TeeTickstamp(
	_ context.Context,
	attestationKey *rsa.PublicKey,
	tickstampSignedEvidencePiece *evidence.SignedEvidencePiece,
	teeSignedEvidencePiece *evidence.SignedEvidencePiece,
) (*tpm2.TPMSTimeAttestInfo, error) {
	attest, err := tpm2.Unmarshal[tpm2.TPM2BAttest](tickstampSignedEvidencePiece.Data)

	if err != nil {
		return nil, err
	}

	attestContents, err := attest.Contents()

	if err != nil {
		return nil, err
	}

	tickstampInfo, err := attestContents.Attested.Time()

	if err != nil {
		return nil, err
	}

	signature, err := tpm2.Unmarshal[tpm2.TPMTSignature](tickstampSignedEvidencePiece.Signature)
	if err != nil {
		return nil, err
	}

	rsassaSignature, err := signature.Signature.RSASSA()

	if err != nil {
		return nil, err
	}

	attestHash := sha256.Sum256(tpm2.Marshal(attestContents))

	err = rsa.VerifyPKCS1v15(attestationKey, crypto.SHA256, attestHash[:], rsassaSignature.Sig.Buffer)

	if err != nil {
		return nil, err
	}

	teeReportHash := sha256.Sum256(teeSignedEvidencePiece.Data)

	if !bytes.Equal(attestContents.ExtraData.Buffer, teeReportHash[:]) {
		return nil, errors.New("unexpected extra data")
	}

	return tickstampInfo, nil
}
