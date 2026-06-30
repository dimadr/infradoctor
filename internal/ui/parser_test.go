package ui

import (
	"testing"
)

func TestParseSelection_Single(t *testing.T) {
	nums, err := ParseSelection("2", 5)
	if err != nil {
		t.Fatal(err)
	}
	if len(nums) != 1 || nums[0] != 2 {
		t.Errorf("got %v, want [2]", nums)
	}
}

func TestParseSelection_Multiple(t *testing.T) {
	nums, err := ParseSelection("1,3,5", 5)
	if err != nil {
		t.Fatal(err)
	}
	want := []int{1, 3, 5}
	if len(nums) != len(want) {
		t.Fatalf("got %v, want %v", nums, want)
	}
	for i, n := range want {
		if nums[i] != n {
			t.Errorf("nums[%d]=%d, want %d", i, nums[i], n)
		}
	}
}

func TestParseSelection_OutOfRange(t *testing.T) {
	_, err := ParseSelection("1,10", 5)
	if err == nil {
		t.Error("expected error for out-of-range number")
	}
}

func TestParseSelection_Duplicate(t *testing.T) {
	_, err := ParseSelection("1,1", 5)
	if err == nil {
		t.Error("expected error for duplicate")
	}
}

func TestParseSelection_Invalid(t *testing.T) {
	_, err := ParseSelection("abc", 5)
	if err == nil {
		t.Error("expected error for non-numeric input")
	}
}

func TestParseSelection_Empty(t *testing.T) {
	_, err := ParseSelection("", 5)
	if err == nil {
		t.Error("expected error for empty input")
	}
}
