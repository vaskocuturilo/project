package connection

import (
	"testing"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo/integration/mtest"
)

func TestNewMongoClient_Mock(t *testing.T) {
	mt := mtest.New(t, mtest.NewOptions().ClientType(mtest.Mock))

	mt.Run("success_connection", func(mt *mtest.T) {
		mt.AddMockResponses(mtest.CreateSuccessResponse())
		client, err := NewMongoClient("mongodb://localhost:27017")
		if err != nil {
			t.Fatalf("Expected no error, got: %v", err)
		}
		if client == nil {
			t.Fatal("Expected client to be initialized, got nil")
		}
	})

	mt.Run("fail_ping", func(mt *mtest.T) {
		mt.AddMockResponses(bson.D{
			{Key: "ok", Value: 0},
			{Key: "errmsg", Value: "network unreachable"},
			{Key: "code", Value: 1},
		})

		client, err := NewMongoClient("mongodb://invalid-uri")

		if err == nil {
			t.Fatal("Expected error during ping, but got none")
		}
		if client != nil {
			t.Error("Expected client to be nil on failed connection")
		}
	})

}
