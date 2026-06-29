package clavex

import (
	"fmt"
	"net/url"
	"strconv"
)

// ── Pagination ─────────────────────────────────────────────────────────────────

// Page is a single page of results returned by cursor-paginated list methods.
//
//	page, err := client.Users.ListPage(ctx, orgID, clavex.ListOptions{Limit: 50})
//	for _, u := range page.Items {
//	    fmt.Println(u.Email)
//	}
//	if page.NextCursor != "" {
//	    next, err := client.Users.ListPage(ctx, orgID, clavex.ListOptions{
//	        Cursor: page.NextCursor, Limit: 50,
//	    })
//	}
type Page[T any] struct {
	Items      []T    `json:"items"`
	Total      int    `json:"total,omitempty"`
	NextCursor string `json:"next_cursor,omitempty"`
	PrevCursor string `json:"prev_cursor,omitempty"`
	HasMore    bool   `json:"has_more,omitempty"`
}

// ListOptions carries optional parameters for paginated list calls.
//
// Not all fields are honoured by every endpoint — unused fields are ignored.
type ListOptions struct {
	// Cursor is the opaque pagination cursor returned in the previous Page.
	// Leave empty to fetch the first page.
	Cursor string
	// Limit is the maximum number of items to return (0 = server default).
	Limit int
	// Page is the 1-based page number for offset-based endpoints.
	Page int
	// PerPage is the page size for offset-based endpoints.
	PerPage int
}

// queryString encodes ListOptions as URL query parameters.
func (o ListOptions) queryString() string {
	v := url.Values{}
	if o.Cursor != "" {
		v.Set("cursor", o.Cursor)
	}
	if o.Limit > 0 {
		v.Set("limit", strconv.Itoa(o.Limit))
	}
	if o.Page > 0 {
		v.Set("page", strconv.Itoa(o.Page))
	}
	if o.PerPage > 0 {
		v.Set("per_page", strconv.Itoa(o.PerPage))
	}
	return v.Encode()
}

// withQuery appends ListOptions to a path as a query string.
func withQuery(path string, opts ListOptions) string {
	q := opts.queryString()
	if q == "" {
		return path
	}
	return fmt.Sprintf("%s?%s", path, q)
}
