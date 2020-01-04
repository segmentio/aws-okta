package configload

import "testing"

func TestGetConfigValue(t *testing.T) {
	config_profiles := make(Profiles)

	t.Run("empty profile", func(t *testing.T) {
		_, _, found_error := config_profiles.GetValue("profile_a", "config_key")
		if found_error == nil {
			t.Error("Searching an empty profile set should return an error")
		}
	})

	config_profiles["okta"] = map[string]string{
		"key_a": "a",
		"key_b": "b",
	}

	config_profiles["profile_a"] = map[string]string{
		"key_b": "b-a",
		"key_c": "c-a",
		"key_d": "d-a",
	}

	config_profiles["profile_b"] = map[string]string{
		"source_profile": "profile_a",
		"key_d":          "d-b",
		"key_e":          "e-b",
	}

	config_profiles["profile_c"] = map[string]string{
		"source_profile": "profile_b",
		"key_f":          "f-c",
	}

	t.Run("missing key", func(t *testing.T) {
		_, _, found_error := config_profiles.GetValue("profile_a", "config_key")
		if found_error == nil {
			t.Error("Searching for a missing key should return an error")
		}
	})

	t.Run("fallback to okta", func(t *testing.T) {
		found_value, found_profile, found_error := config_profiles.GetValue("profile_a", "key_a")
		if found_error != nil {
			t.Error("Error when searching for key_a")
		}

		if found_profile != "okta" {
			t.Error("key_a should have come from `okta`")
		}

		if found_value != "a" {
			t.Error("The proper value for `key_a` should be `a`")
		}
	})

	t.Run("found in current profile", func(t *testing.T) {
		found_value, found_profile, found_error := config_profiles.GetValue("profile_b", "key_d")
		if found_error != nil {
			t.Error("Error when searching for key_d")
		}

		if found_profile != "profile_b" {
			t.Error("key_d should have come from `profile_b`")
		}

		if found_value != "d-b" {
			t.Error("The proper value for `key_d` should be `d-b`")
		}
	})

	t.Run("traversing from child profile", func(t *testing.T) {
		found_value, found_profile, found_error := config_profiles.GetValue("profile_b", "key_a")
		if found_error != nil {
			t.Error("Error when searching for key_a")
		}

		if found_profile != "okta" {
			t.Error("key_a should have come from `okta`")
		}

		if found_value != "a" {
			t.Error("The proper value for `key_a` should be `a`")
		}
	})

	t.Run("recursive traversing from child profile", func(t *testing.T) {
		_, _, found_error := config_profiles.GetValue("profile_c", "key_c")
		if found_error == nil {
			t.Error("Recursive searching should not work")
		}
	})
}
