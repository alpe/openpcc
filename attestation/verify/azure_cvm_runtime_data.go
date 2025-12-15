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
package verify

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"reflect"

	"github.com/google/go-cmp/cmp"
	"github.com/openpcc/openpcc/attestation/evidence"
)

// Validate the azure CVM runtime data and return the expected nonce for the TEE report
func AzureCVMRuntimeData(
	ctx context.Context,
	signedEvidencePiece *evidence.SignedEvidencePiece,
) ([]byte, error) {
	runtimeData := &evidence.AzureCVMRuntimeData{}
	err := runtimeData.UnmarshalBinary(signedEvidencePiece.Data)

	if err != nil {
		return nil, fmt.Errorf("failed to parse runtime data (%v): %w", signedEvidencePiece.Data, err)
	}

	runtimeDataInJson := &evidence.AzureCVMRuntimeData{}
	err = runtimeDataInJson.UnmarshalJSON(runtimeData.OriginalJSON)

	if err != nil {
		return nil, fmt.Errorf("failed to parse runtime data from original json (%v): %w", runtimeData.OriginalJSON, err)
	}

	if !reflect.DeepEqual(runtimeData, runtimeDataInJson) {
		return nil, errors.New("struct does not match its original json: " + cmp.Diff(runtimeData, runtimeDataInJson))
	}

	originalJsonHash := sha256.Sum256(runtimeData.OriginalJSON)

	if !bytes.Equal(originalJsonHash[:], runtimeData.Signature[:]) {
		return nil, errors.New("signatures do not match")
	}

	if !bytes.Equal(originalJsonHash[:], signedEvidencePiece.Signature) {
		return nil, errors.New("signatures do not match")
	}

	expectedNoncePadded, err := evidence.PadByteArrayTo64(runtimeData.Signature[:])

	if err != nil {
		return nil, fmt.Errorf("nonce too long: %x", runtimeData.Signature[:])
	}

	return expectedNoncePadded, nil
}
