package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	type testCase struct {
		header http.Header
		want   string
		err    error
	}

	t.Run("Should work for a valid headers", func(t *testing.T) {
		cases := []testCase{
			{
				header: http.Header{"Authorization": []string{"ApiKey SomeValue"}},
				want:   "SomeValue",
				err:    nil,
			},
			{
				header: http.Header{"Authorization": []string{"ApiKey SomeOtherValue"}},
				want:   "SomeOtherValue",
				err:    nil,
			},
		}

		for _, c := range cases {
			got, err := GetAPIKey(c.header)
			if err != c.err {
				t.Errorf("Error happened: %s", err)
				continue
			}
			if got != c.want {
				t.Errorf("got %s, want %s", got, c.want)
			}
		}
	})

	t.Run("Should not work for invalid headers", func(t *testing.T) {
		cases := []testCase{
			{
				header: http.Header{"": []string{}},
				want:   "",
				err:    ErrNoAuthHeaderIncluded,
			},
			{
				header: http.Header{"Authorization": []string{"Bearer SomeOtherValue"}},
				want:   "",
				err:    errors.New("malformed authorization header"),
			},
		}

		for _, c := range cases {
			got, err := GetAPIKey(c.header)
			if got != c.want {
				t.Errorf("got %s, want %s", got, c.want)
			}
			assertError(t, err, c.err)
		}
	})
}

func assertError(t testing.TB, got, want error) {
	t.Helper()

	if !errors.Is(got, want) {
		if got.Error() != want.Error() {
			t.Errorf("got err %s, want err %s", got, want)
		}
	}

}
