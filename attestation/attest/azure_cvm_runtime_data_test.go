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
package attest_test

import (
	"bytes"
	_ "embed"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/google/go-tpm/tpm2/transport/simulator"
	"github.com/openpcc/openpcc/attestation/attest"
	"github.com/openpcc/openpcc/attestation/evidence"
	"github.com/openpcc/openpcc/attestation/verify"
	test "github.com/openpcc/openpcc/inttest"
)

func Test_AzureCVMRuntimeData_Success(t *testing.T) {
	reportFS := test.TextArchiveFS(t, "testdata/azure_sevsnp_report.txt")
	testAzureSEVSNPReportPEM := test.ReadFile(t, reportFS, "test_azure_sevsnp_report.pem")

	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	block, _ := pem.Decode(testAzureSEVSNPReportPEM)
	require.NotNil(t, block)

	mocktpm := &TPMNVWrapper{
		realtpm:       thetpm,
		responseBytes: block.Bytes,
	}

	attestor := attest.NewAzureCVMRuntimeDataAttestor(
		mocktpm,
		make([]byte, 64),
	)
	se, err := attestor.CreateSignedEvidence(t.Context())

	runtimeData := &evidence.AzureCVMRuntimeData{}
	runtimeData.UnmarshalBinary(se.Data)

	require.NoError(t, err)
	require.NotNil(t, se)

	expectedNonce, err := verify.AzureCVMRuntimeData(t.Context(), se)
	observedNoncePadded, err := evidence.PadByteArrayTo64(runtimeData.Signature[:])
	require.Equal(t,
		observedNoncePadded,
		expectedNonce,
	)
}

func Test_AzureCVMRuntimeData_FailureSignatureMismatch(t *testing.T) {
	reportFS := test.TextArchiveFS(t, "testdata/azure_sevsnp_report.txt")
	testAzureSEVSNPReportPEM := test.ReadFile(t, reportFS, "test_azure_sevsnp_report.pem")

	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}

	t.Cleanup(func() {
		if err := thetpm.Close(); err != nil {
			t.Errorf("%v", err)
		}
	})

	block, _ := pem.Decode(testAzureSEVSNPReportPEM)
	require.NotNil(t, block)

	mocktpm := &TPMNVWrapper{
		realtpm:       thetpm,
		responseBytes: block.Bytes,
	}

	attestor := attest.NewAzureCVMRuntimeDataAttestor(
		mocktpm,
		make([]byte, 64),
	)
	se, err := attestor.CreateSignedEvidence(t.Context())

	require.NoError(t, err)
	require.NotNil(t, se)

	runtimeData := &evidence.AzureCVMRuntimeData{}
	runtimeData.UnmarshalBinary(se.Data)

	// Modify the proto in some way
	runtimeData.AzureCVMConfiguration.TpmEnabled = false

	newBytes, err := runtimeData.MarshalBinary()
	require.NoError(t, err)
	require.NotNil(t, newBytes)

	se.Data = newBytes

	_, err = verify.AzureCVMRuntimeData(t.Context(), se)

	require.ErrorContains(t, err, "struct does not match its original json")
}

func Test_ExtractJSONObjectWithTrailingHeadingBytes(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		want      []byte
		expectErr bool
	}{
		{
			name:      "Standard extraction with binary noise",
			input:     []byte{0x00, 0x01, '{', '"', 'k', '"', ':', '1', '}', 0xFF, 0xFE},
			want:      []byte(`{"k":1}`),
			expectErr: false,
		},
		{
			name:      "Clean JSON without noise",
			input:     []byte(`{"foo":"bar"}`),
			want:      []byte(`{"foo":"bar"}`),
			expectErr: false,
		},
		{
			name:      "Nested JSON objects",
			input:     []byte(`prefix{"parent":{"child":"value"}}suffix`),
			want:      []byte(`{"parent":{"child":"value"}}`),
			expectErr: false,
		},
		{
			name: "Multiple JSON objects",
			// Note: The function logic captures from the *first* { to the *last* }.
			// This test confirms that greedy behavior, even if the result isn't valid single-root JSON.
			input:     []byte(`noise{"obj1":1} garbage {"obj2":2}noise`),
			want:      []byte(`{"obj1":1} garbage {"obj2":2}`),
			expectErr: false,
		},
		{
			name:      "No opening brace",
			input:     []byte(`json content without open brace}`),
			want:      nil,
			expectErr: true,
		},
		{
			name:      "No closing brace",
			input:     []byte(`{json content without close brace`),
			want:      nil,
			expectErr: true,
		},
		{
			name:      "No braces at all",
			input:     []byte(`just random text`),
			want:      nil,
			expectErr: true,
		},
		{
			name:      "Braces in wrong order (closing before opening)",
			input:     []byte(`junk} middle {junk`),
			want:      nil,
			expectErr: true,
		},
		{
			name:      "Empty input",
			input:     []byte{},
			want:      nil,
			expectErr: true,
		},
		{
			name:      "Only braces",
			input:     []byte(`{}`),
			want:      []byte(`{}`),
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := attest.ExtractJSONObjectWithTrailingHeadingBytes(tt.input)
			if (err != nil) != tt.expectErr {
				t.Errorf("extractJSONObject() error = %v, expectErr %v", err, tt.expectErr)
				return
			}

			if !bytes.Equal(got, tt.want) {
				t.Errorf("extractJSONObject() got = %s, want %s", got, tt.want)
			}
		})
	}
}
