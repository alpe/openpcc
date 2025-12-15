// Copyright 2025 Nonvolatile Inc. d/b/a Confident Security

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     https://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package attest

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/google/go-tpm/tpmutil"
	"github.com/openpcc/openpcc/attestation/evidence"
	cstpm "github.com/openpcc/openpcc/tpm"
)

type AzureCVMRuntimeDataAttestor struct {
	tpm   transport.TPM
	Nonce []byte
}

func NewAzureCVMRuntimeDataAttestor(tpm transport.TPM, nonce []byte) *AzureCVMRuntimeDataAttestor {
	return &AzureCVMRuntimeDataAttestor{
		tpm:   tpm,
		Nonce: nonce,
	}
}

func (*AzureCVMRuntimeDataAttestor) Name() string {
	return "AzureCVMRuntimeDataAttestor"
}

func ParseAzureCVMRuntimeDataFromReport(raw []byte) (*evidence.AzureCVMRuntimeData, error) {
	rawJsonBytesWithHeaderTrailer := raw[(AzureSEVSNPReportOffset + AzureSEVSNPReportSize):]
	rawJsonBytesTrimmed, err := ExtractJSONObjectWithTrailingHeadingBytes(rawJsonBytesWithHeaderTrailer)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal runtime data: %w", err)
	}

	runtimeData := &evidence.AzureCVMRuntimeData{}

	err = runtimeData.UnmarshalJSON(rawJsonBytesTrimmed)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal runtime data: %w", err)
	}
	return runtimeData, nil
}

func (a *AzureCVMRuntimeDataAttestor) CreateSignedEvidence(ctx context.Context) (*evidence.SignedEvidencePiece, error) {
	err := cstpm.WriteToNVRamNoAuth(
		a.tpm,
		tpmutil.Handle(AzureTDReportWriteNVIndex),
		a.Nonce)

	if err != nil {
		return nil, fmt.Errorf(
			"failed to write empty nonce to NV index (%x): %w",
			AzureTDReportWriteNVIndex,
			err)
	}

	raw, err := cstpm.NVReadEXNoAuthorization(a.tpm, tpmutil.Handle(AzureTDReportReadNVIndex))
	if err != nil {
		return nil, fmt.Errorf("failed to read TD report from NV index (%x): %w", AzureTDReportReadNVIndex, err)
	}

	runtimeData, err := ParseAzureCVMRuntimeDataFromReport(raw)

	if err != nil {
		return nil, err
	}

	runtimeDataSerialized, err := runtimeData.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal runtime data to proto: %w", err)
	}

	return &evidence.SignedEvidencePiece{
		Data:      runtimeDataSerialized,
		Signature: runtimeData.Signature[:],
		Type:      evidence.AzureRuntimeData,
	}, nil
}

// The exact offsets of the json runtime information in the raw binary output from the vTPM are not defined.
// Given that fact that its a variable length structure we will use this streaming json parser to extract it.
func ExtractJSONObjectWithTrailingHeadingBytes(data []byte) ([]byte, error) {
	firstBrace := -1
	for i := 0; i < len(data); i++ {
		if data[i] == '{' {
			firstBrace = i
			break
		}
	}

	if firstBrace == -1 {
		return nil, errors.New("no JSON object found in data")
	}

	lastBrace := -1
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] == '}' {
			lastBrace = i
			break
		}
	}

	if lastBrace == -1 {
		return nil, errors.New("no JSON object found in data")
	}

	if lastBrace < firstBrace {
		return nil, errors.New("no JSON object found in data")
	}

	return data[firstBrace : lastBrace+1], nil
}
