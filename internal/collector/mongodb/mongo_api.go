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

package mongodb

import (
	"context"

	"go.mongodb.org/mongo-driver/v2/mongo"
)

// mongoAPI is the minimal surface of the MongoDB driver used by the collect
// functions. Abstracting it behind an interface lets the collectors be driven
// by a hand-written fake in unit tests without a real database.
type mongoAPI interface {
	// RunCommand runs an admin/database command and decodes the single-document
	// result into out.
	RunCommand(ctx context.Context, db string, cmd interface{}, out interface{}) error
	// FindOne runs a collection find and decodes the first document into out.
	FindOne(ctx context.Context, db, coll string, filter interface{}, out interface{}) error
	// Find runs a collection find and decodes all documents into out (a pointer
	// to a slice).
	Find(ctx context.Context, db, coll string, filter interface{}, out interface{}) error
	// Aggregate runs an aggregation pipeline and decodes all documents into out
	// (a pointer to a slice).
	Aggregate(ctx context.Context, db, coll string, pipeline interface{}, out interface{}) error
	// ListCollectionNames returns the collection names for a database.
	ListCollectionNames(ctx context.Context, db string, filter interface{}) ([]string, error)
}

// clientAPI is the production implementation of mongoAPI backed by a real
// *mongo.Client.
type clientAPI struct {
	client *mongo.Client
}

func newClientAPI(client *mongo.Client) clientAPI {
	return clientAPI{client: client}
}

func (a clientAPI) RunCommand(ctx context.Context, db string, cmd interface{}, out interface{}) error {
	return a.client.Database(db).RunCommand(ctx, cmd).Decode(out)
}

func (a clientAPI) FindOne(ctx context.Context, db, coll string, filter interface{}, out interface{}) error {
	return a.client.Database(db).Collection(coll).FindOne(ctx, filter).Decode(out)
}

func (a clientAPI) Find(ctx context.Context, db, coll string, filter interface{}, out interface{}) error {
	cursor, err := a.client.Database(db).Collection(coll).Find(ctx, filter)
	if err != nil {
		return err
	}
	defer func() { _ = cursor.Close(ctx) }()
	return cursor.All(ctx, out)
}

func (a clientAPI) Aggregate(ctx context.Context, db, coll string, pipeline interface{}, out interface{}) error {
	cursor, err := a.client.Database(db).Collection(coll).Aggregate(ctx, pipeline)
	if err != nil {
		return err
	}
	defer func() { _ = cursor.Close(ctx) }()
	return cursor.All(ctx, out)
}

func (a clientAPI) ListCollectionNames(ctx context.Context, db string, filter interface{}) ([]string, error) {
	return a.client.Database(db).ListCollectionNames(ctx, filter)
}
