package sheet_test

import (
	"archive/zip"
	"bytes"
	"strconv"
	"strings"
	"testing"

	"github.com/UnityEvolv/b2b-backend-template/pkg/sheet"
)

func TestCSV(t *testing.T) {
	csv := "\xef\xbb\xbfEmail, Full Name ,Role\nada@example.com,Ada Lovelace,admin\n\n\"bob@example.com\",\"Bob, Jr.\",\nshort\n"
	tb, err := sheet.Read([]byte(csv))
	if err != nil {
		t.Fatal(err)
	}
	if len(tb.Header) != 3 || tb.Header[1] != "Full Name" || tb.Column(" full name ") != 1 || tb.Column("nope") != -1 {
		t.Errorf("header: %v", tb.Header)
	}
	if len(tb.Rows) != 3 || tb.Rows[1][1] != "Bob, Jr." || sheet.Cell(tb.Rows[2], 2) != "" || tb.Rows[0][2] != "admin" {
		t.Errorf("rows: %v", tb.Rows)
	}
	if _, err := sheet.Read([]byte("\n\n")); err != sheet.ErrEmpty {
		t.Errorf("empty: %v", err)
	}
	var big strings.Builder
	big.WriteString("email\n")
	for i := 0; i < sheet.MaxRows+5; i++ {
		big.WriteString("x@example.com\n")
	}
	if _, err := sheet.Read([]byte(big.String())); err != sheet.ErrTooLarge {
		t.Errorf("too many rows: %v", err)
	}
}

// xlsx builds a workbook with one sheet from rows, using shared strings
// for text and inline numbers, as Excel and Sheets write them.
func xlsx(t *testing.T, rows [][]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	z := zip.NewWriter(&buf)
	var shared []string
	index := func(s string) int {
		for i, v := range shared {
			if v == s {
				return i
			}
		}
		shared = append(shared, s)
		return len(shared) - 1
	}
	var sheetXML strings.Builder
	sheetXML.WriteString(`<?xml version="1.0"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>`)
	for r, row := range rows {
		sheetXML.WriteString(`<row r="` + itoa(r+1) + `">`)
		for c, cell := range row {
			if cell == "" {
				continue
			}
			ref := string(rune('A'+c)) + itoa(r+1)
			if _, err := parseFloat(cell); err == nil {
				sheetXML.WriteString(`<c r="` + ref + `"><v>` + cell + `</v></c>`)
			} else {
				sheetXML.WriteString(`<c r="` + ref + `" t="s"><v>` + itoa(index(cell)) + `</v></c>`)
			}
		}
		sheetXML.WriteString(`</row>`)
	}
	sheetXML.WriteString(`</sheetData></worksheet>`)
	var sst strings.Builder
	sst.WriteString(`<?xml version="1.0"?><sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">`)
	for _, s := range shared {
		sst.WriteString(`<si><t>` + s + `</t></si>`)
	}
	sst.WriteString(`</sst>`)
	for name, content := range map[string]string{"xl/worksheets/sheet1.xml": sheetXML.String(), "xl/sharedStrings.xml": sst.String(), "[Content_Types].xml": `<Types/>`} {
		w, _ := z.Create(name)
		w.Write([]byte(content))
	}
	z.Close()
	return buf.Bytes()
}

func itoa(i int) string { return strconv.Itoa(i) }

func parseFloat(s string) (float64, error) { return strconv.ParseFloat(s, 64) }

func TestXLSX(t *testing.T) {
	data := xlsx(t, [][]string{{"Email", "Name", "Seat"}, {"ada@example.com", "Ada", "7"}, {"", "Nobody", ""}, {"bob@example.com", "", "3"}})
	tb, err := sheet.Read(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(tb.Header) != 3 || tb.Column("email") != 0 {
		t.Errorf("header: %v", tb.Header)
	}
	if len(tb.Rows) != 3 || tb.Rows[0][0] != "ada@example.com" || tb.Rows[0][2] != "7" || sheet.Cell(tb.Rows[1], 0) != "" || tb.Rows[1][1] != "Nobody" || tb.Rows[2][1] != "" {
		t.Errorf("rows: %v", tb.Rows)
	}
	if _, err := sheet.Read([]byte("PK\x03\x04garbage")); err == nil {
		t.Error("garbage zip accepted")
	}
}
