package main_test

import (
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	"todo-service/internal/model"
)

func TestMain(t *testing.T) {
	todo := &model.Task{
		Id:          "TASK-0001",
		Title:       "Proyekan",
		Status:      "0",
		Description: "lorem ipsum dorem",
		DueDate:     nil,
		UserId:      "1",
	}

	jsonb, err := protojson.Marshal(todo)
	if err != nil {
		t.Logf("error on marshal jsonb: %v", err)
	}

	protoObj := new(model.Task)
	err = protojson.Unmarshal(jsonb, protoObj)
	if err != nil {
		t.Logf("error on unmarshar jsonb: %v", err)
	}

	t.Logf("task id: %v", protoObj.Id)
	t.Logf("jsonb: %v", jsonb)
	t.Logf("protoObj: %v", protoObj)
}
