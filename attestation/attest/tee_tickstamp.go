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

package attest

import (
	"context"
	"crypto/sha256"
	"slices"

	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"github.com/openpcc/openpcc/attestation/evidence"
	cstpm "github.com/openpcc/openpcc/tpm"
)

var (
	teeReportTypes = []evidence.EvidenceType{
		evidence.SevSnpReport,
		evidence.SevSnpExtendedReport,
		evidence.TdxReport,
	}
)

type TeeTickstampAttestor struct {
	tpm                  transport.TPM
	attestationKeyHandle tpmutil.Handle
	teeEvidencePiece     *evidence.SignedEvidencePiece
}

func NewTeeTickstampAttestor(
	tpm transport.TPM,
	attestationKeyHandle tpmutil.Handle,
	teeEvidencePiece *evidence.SignedEvidencePiece,
) *TeeTickstampAttestor {
	return &TeeTickstampAttestor{
		tpm:                  tpm,
		attestationKeyHandle: attestationKeyHandle,
		teeEvidencePiece:     teeEvidencePiece,
	}
}

func (*TeeTickstampAttestor) Name() string {
	return "TeeTickstampAttestor"
}

// Tickstamp the contents of a trust domain report. This will link the trust domain report to a TPM attestation key
// at a particular point in time.
func (a *TeeTickstampAttestor) CreateSignedEvidence(_ context.Context) (*evidence.SignedEvidencePiece, error) {
	if !slices.Contains(teeReportTypes, a.teeEvidencePiece.Type) {
		return nil, fmt.Errorf("not a TEE report type: %v", a.teeEvidencePiece.Type)
	}

	hash := sha256.Sum256(a.teeEvidencePiece.Data)

	tickstamp, err := cstpm.TickstampData(
		a.tpm,
		tpm2.TPMHandle(a.attestationKeyHandle),
		hash[:],
	)

	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	return &evidence.SignedEvidencePiece{
		Type:      evidence.TeeTickstamp,
		Data:      tpm2.Marshal(tickstamp.TimeInfo),
		Signature: tpm2.Marshal(tickstamp.Signature),
	}, nil
}
