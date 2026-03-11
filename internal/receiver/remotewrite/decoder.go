// Package remotewrite implements a Prometheus Remote Write receiver that
// accepts push-based metrics over HTTP and forwards them to the TelemetryFlow
// Agent export pipeline.
//
// TelemetryFlow Agent - Community Enterprise Observability Platform
// Copyright (c) 2024-2026 TelemetryFlow. All rights reserved.
// Open Source Software built by DevOpsCorner Indonesia.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package remotewrite

import (
	"fmt"

	"github.com/golang/snappy"
	"github.com/prometheus/prometheus/prompb"
)

// decodeWriteRequest decompresses a Snappy-encoded body and unmarshals it into
// a prometheus WriteRequest protobuf message.
func decodeWriteRequest(body []byte) (*prompb.WriteRequest, error) {
	decoded, err := snappy.Decode(nil, body)
	if err != nil {
		return nil, fmt.Errorf("snappy decode: %w", err)
	}

	var req prompb.WriteRequest
	if err := req.Unmarshal(decoded); err != nil {
		return nil, fmt.Errorf("protobuf unmarshal: %w", err)
	}

	return &req, nil
}
