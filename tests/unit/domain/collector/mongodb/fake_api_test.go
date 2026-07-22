// Package mongodb_test contains unit tests for the corresponding collector module.
//
// TelemetryFlow Agent - AI-Powered Observability & Incident Response Management (IRM) Platform
// Copyright (c) 2024-2026 Telemetri Data Indonesia. All rights reserved.
// Open Source Software built by Telemetri Data Indonesia.
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
package mongodb_test

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/telemetryflow/telemetryflow-agent/internal/collector"
)

// fakeAPI is a hand-written implementation of mongodb.MongoAPI that returns
// canned bson results per (operation,db,collection) key, enabling deterministic
// unit tests without a real MongoDB instance.
type fakeAPI struct {
	// runCommand results keyed by "db|<command-name>".
	runCommand map[string]cannedResult
	// findOne results keyed by "db.coll".
	findOne map[string]cannedResult
	// find results keyed by "db.coll" -> slice of docs.
	find map[string]cannedSlice
	// aggregate results keyed by "db.coll" -> slice of docs.
	aggregate map[string]cannedSlice
	// listCollections results keyed by "db".
	listCollections map[string]cannedNames
}

type cannedResult struct {
	doc bson.M
	err error
}

type cannedSlice struct {
	docs []bson.M
	err  error
}

type cannedNames struct {
	names []string
	err   error
}

func newFakeAPI() *fakeAPI {
	return &fakeAPI{
		runCommand:      map[string]cannedResult{},
		findOne:         map[string]cannedResult{},
		find:            map[string]cannedSlice{},
		aggregate:       map[string]cannedSlice{},
		listCollections: map[string]cannedNames{},
	}
}

// commandName extracts the first key of a bson.D command document.
func commandName(cmd interface{}) string {
	if d, ok := cmd.(bson.D); ok && len(d) > 0 {
		return d[0].Key
	}
	return ""
}

func (f *fakeAPI) RunCommand(_ context.Context, db string, cmd interface{}, out interface{}) error {
	key := db + "|" + commandName(cmd)
	res, ok := f.runCommand[key]
	if !ok {
		return fmt.Errorf("fakeAPI: no canned RunCommand for %q", key)
	}
	if res.err != nil {
		return res.err
	}
	return decodeInto(res.doc, out)
}

func (f *fakeAPI) FindOne(_ context.Context, db, coll string, _ interface{}, out interface{}) error {
	key := db + "." + coll
	res, ok := f.findOne[key]
	if !ok {
		return fmt.Errorf("fakeAPI: no canned FindOne for %q", key)
	}
	if res.err != nil {
		return res.err
	}
	return decodeInto(res.doc, out)
}

func (f *fakeAPI) Find(_ context.Context, db, coll string, _ interface{}, out interface{}) error {
	key := db + "." + coll
	res, ok := f.find[key]
	if !ok {
		return fmt.Errorf("fakeAPI: no canned Find for %q", key)
	}
	if res.err != nil {
		return res.err
	}
	return decodeSlice(res.docs, out)
}

func (f *fakeAPI) Aggregate(_ context.Context, db, coll string, _ interface{}, out interface{}) error {
	key := db + "." + coll
	res, ok := f.aggregate[key]
	if !ok {
		return fmt.Errorf("fakeAPI: no canned Aggregate for %q", key)
	}
	if res.err != nil {
		return res.err
	}
	return decodeSlice(res.docs, out)
}

func (f *fakeAPI) ListCollectionNames(_ context.Context, db string, _ interface{}) ([]string, error) {
	res, ok := f.listCollections[db]
	if !ok {
		return nil, fmt.Errorf("fakeAPI: no canned ListCollectionNames for %q", db)
	}
	return res.names, res.err
}

// decodeInto assigns a canned bson.M into a *bson.M target (the only decode
// target the collectors use for single documents).
func decodeInto(doc bson.M, out interface{}) error {
	target, ok := out.(*bson.M)
	if !ok {
		return fmt.Errorf("fakeAPI: unsupported decode target %T", out)
	}
	*target = doc
	return nil
}

// decodeSlice assigns canned docs into a *[]bson.M target.
func decodeSlice(docs []bson.M, out interface{}) error {
	target, ok := out.(*[]bson.M)
	if !ok {
		return fmt.Errorf("fakeAPI: unsupported slice decode target %T", out)
	}
	*target = docs
	return nil
}

// metricByName finds the first metric with the given name.
func metricByName(metrics []collector.Metric, name string) (collector.Metric, bool) {
	for _, m := range metrics {
		if m.Name == name {
			return m, true
		}
	}
	return collector.Metric{}, false
}

// requireValue asserts a metric exists with the given name and value.
func requireValue(t interface {
	Helper()
	Errorf(string, ...interface{})
}, metrics []collector.Metric, name string, want float64) {
	t.Helper()
	m, ok := metricByName(metrics, name)
	if !ok {
		t.Errorf("metric %q not found", name)
		return
	}
	if m.Value != want {
		t.Errorf("metric %q = %v, want %v", name, m.Value, want)
	}
}
