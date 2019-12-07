package lib

import "testing"

func TestGetConfigValue(t *testing.T) {
	config_profiles := make(Profiles)

	t.Run("empty profile normal value search", func(t *testing.T) {
		_, _, found_error := config_profiles.GetValue("profile_a", "config_key")
		if found_error == nil {
			t.Error("Normal value search of an empty profile set should return an error")
		}
	})

	t.Run("empty profile direct value search", func(t *testing.T) {
		_, _, found_error := config_profiles.GetDirectValue("profile_a", "config_key")
		if found_error == nil {
			t.Error("Direct value search of an empty profile set should return an error")
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

	t.Run("missing key normal value search", func(t *testing.T) {
		_, _, found_error := config_profiles.GetValue("profile_a", "config_key")
		if found_error == nil {
			t.Error("Normal value search for a missing key should return an error")
		}
	})

	t.Run("missing key direct value search", func(t *testing.T) {
		_, _, found_error := config_profiles.GetDirectValue("profile_a", "config_key")
		if found_error == nil {
			t.Error("Direct value search for a missing key should return an error")
		}
	})

	t.Run("fallback to okta on normal value search", func(t *testing.T) {
		found_value, found_profile, found_error := config_profiles.GetValue("profile_a", "key_a")
		if found_error != nil {
			t.Error("Error when performing normal value search for key_a")
		}

		if found_profile != "okta" {
			t.Error("key_a should have come from `okta`")
		}

		if found_value != "a" {
			t.Error("The proper value for `key_a` should be `a`")
		}
	})

	t.Run("no fallback to okta on direct value search", func(t *testing.T) {
		found_value, found_profile, found_error := config_profiles.GetDirectValue("profile_a", "key_a")
		if found_error == nil {
			t.Error("Direct value search for key missing from top-level should return an error")
		}

		if found_profile != "" {
			t.Error("key_a should not have been found in any profile")
		}

		if found_value != "" {
			t.Error("No value should have been found for `key_a`")
		}
	})

	t.Run("normal value search for item found in current profile", func(t *testing.T) {
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

	t.Run("direct value search for item found in current profile", func(t *testing.T) {
		found_value, found_profile, found_error := config_profiles.GetDirectValue("profile_b", "key_d")
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
