package test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/lightninglabs/taproot-assets/fn"
	"github.com/pmezard/go-difflib/difflib"
)

// FillFakeData recursively fills a struct with dummy values.
func FillFakeData[T any](t *testing.T, debug bool, maxDepth int, v T) {
	if t != nil {
		t.Helper()
	}

	val := reflect.ValueOf(v)
	name := val.Type().Elem().Name()
	fillFakeData(t, debug, 0, maxDepth, val, name)
}

// fillFakeData is the recursive helper to fill a value with fake data.
func fillFakeData(t *testing.T, debug bool, depth, maxDepth int,
	v reflect.Value, path string) {

	if t != nil {
		t.Helper()
	}

	if depth > maxDepth || !v.IsValid() {
		return
	}

	indent := strings.Repeat(" ", depth)

	log := func(format string, args ...any) {
		if debug {
			if t != nil {
				t.Logf(indent+format, args...)
			} else {
				fmt.Printf(indent+format+"\n", args...)
			}
		}
	}
	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			ptr := reflect.New(v.Type().Elem())
			v.Set(ptr)

			log("ptr: %s (%s)", path, v.Type())
		}

		fillFakeData(t, debug, depth+1, maxDepth, v.Elem(), path)

	case reflect.Struct:
		typ := v.Type()
		for i := range v.NumField() {
			field := v.Field(i)
			fieldType := typ.Field(i)

			if !field.CanSet() {
				continue
			}

			fieldPath := fmt.Sprintf("%s.%s", path, fieldType.Name)
			fillFakeData(
				t, debug, depth+1, maxDepth, field, fieldPath,
			)
		}

	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			// Special case: []byte.
			b := make([]byte, randomLen())
			for i := range b {
				b[i] = byte(rand.Intn(256))
			}

			v.SetBytes(b)
			log("[]byte: %s = %v", path, b)

			return
		}

		elemType := v.Type().Elem()
		length := randomLen()
		slice := reflect.MakeSlice(v.Type(), length, length)

		for i := range length {
			elemPath := fmt.Sprintf("%s[%d]", path, i)

			var elem reflect.Value
			if elemType.Kind() == reflect.Ptr {
				elem = reflect.New(elemType.Elem())

				fillFakeData(
					t, debug, depth+1, maxDepth,
					elem.Elem(), elemPath,
				)
			} else {
				elem = reflect.New(elemType).Elem()

				fillFakeData(
					t, debug, depth+1, maxDepth, elem,
					elemPath,
				)
			}

			slice.Index(i).Set(elem)
		}

		v.Set(slice)
		log("slice: %s (len=%d)", path, length)

	case reflect.Array:
		for i := range v.Len() {
			fillFakeData(
				t, debug, depth+1, maxDepth, v.Index(i),
				fmt.Sprintf("%s[%d]", path, i),
			)
		}

		log("array: %s (len=%d)", path, v.Len())

	case reflect.Map:
		keyType := v.Type().Key()
		valType := v.Type().Elem()
		m := reflect.MakeMap(v.Type())
		length := randomLen()

		for i := range length {
			key := reflect.New(keyType).Elem()

			fillFakeData(
				t, debug, depth+1, maxDepth, key,
				fmt.Sprintf("%s[key%d]", path, i),
			)

			val := reflect.New(valType).Elem()

			fillFakeData(
				t, debug, depth+1, maxDepth, val,
				fmt.Sprintf("%s[val%d]", path, i),
			)

			m.SetMapIndex(key, val)
		}

		v.Set(m)
		log("map: %s (len=%d)", path, length)

	default:
		assignDummyPrimitive(t, debug, indent, v, path)
	}
}

// assignDummyPrimitive assigns dummy values to primitive type values.
func assignDummyPrimitive(t *testing.T, debug bool, indent string,
	v reflect.Value, path string) {

	log := func(format string, args ...any) {
		if debug {
			if t != nil {
				t.Logf(indent+format, args...)
			} else {
				fmt.Printf(indent+format+"\n", args...)
			}
		}
	}

	switch v.Kind() {
	case reflect.String:
		s := randomString()
		v.SetString(s)
		log("string: %s = %q", path, s)

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32,
		reflect.Int64:

		i := rand.Int63n(1_000_000)
		v.SetInt(i)
		log("int: %s = %d", path, i)

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32,
		reflect.Uint64:

		u := uint64(rand.Intn(1_000_000))
		v.SetUint(u)
		log("uint: %s = %d", path, u)

	case reflect.Bool:
		b := rand.Intn(2) == 0
		v.SetBool(b)
		log("bool: %s = %v", path, b)

	case reflect.Float32, reflect.Float64:
		f := rand.Float64() * 1_000
		v.SetFloat(f)
		log("float: %s = %f", path, f)

	default:
	}
}

func randomString() string {
	return fmt.Sprintf("val_%d", rand.Intn(100_000))
}

func randomLen() int {
	return rand.Intn(3)
}

// checkAliasing walks the fields and check for shared references.
func checkAliasing(t *testing.T, debug, strict bool, f1, f2 reflect.Value,
	path string) {

	t.Helper()

	if !f1.IsValid() || !f2.IsValid() {
		return
	}

	switch f1.Kind() {
	case reflect.Ptr, reflect.Slice, reflect.Map, reflect.Func,
		reflect.Chan:

		if f1.IsNil() || f2.IsNil() {
			return
		}

		if f1.Pointer() == f2.Pointer() {
			msg := fmt.Sprintf("Aliasing detected at path: %s "+
				"(shared %s)", path, f1.Kind())

			if strict {
				t.Fatal(msg)
			}

			if debug {
				t.Logf("WARNING %s", msg)
			}
		}

		// Recurse into slice/map values.
		switch f1.Kind() {
		case reflect.Slice:
			for i := 0; i < f1.Len() && i < f2.Len(); i++ {
				checkAliasing(
					t, debug, strict,
					f1.Index(i), f2.Index(i),
					fmt.Sprintf("%s[%d]", path, i),
				)
			}
		case reflect.Map:
			for _, key := range f1.MapKeys() {
				v1 := f1.MapIndex(key)
				v2 := f2.MapIndex(key)
				checkAliasing(
					t, debug, strict,
					v1, v2, fmt.Sprintf("%s[%v]", path,
						key.Interface()),
				)
			}

		default:
		}

	case reflect.Struct:
		for i := range f1.NumField() {
			field := f1.Type().Field(i)

			// Skip unexported fields.
			if !f1.Field(i).CanInterface() {
				continue
			}

			childPath := fmt.Sprintf("%s.%s", path, field.Name)
			checkAliasing(
				t, debug, strict,
				f1.Field(i), f2.Field(i), childPath,
			)
		}

	default:
	}
}

// AssertCopyEqual checks that the Copy method returns a value that:
// 1) is deeply equal
// 2) does not alias mutable fields (pointers, slices, maps)
func AssertCopyEqual[T fn.Copyable[T]](t *testing.T, debug, strict bool,
	original T) {

	originalVal := reflect.ValueOf(original)
	copied := original.Copy()
	copiedVal := reflect.ValueOf(copied)

	if !reflect.DeepEqual(original, copied) {
		diff := difflib.UnifiedDiff{
			A: difflib.SplitLines(
				spew.Sdump(original),
			),
			B: difflib.SplitLines(
				spew.Sdump(copied),
			),
			FromFile: "Original",
			FromDate: "",
			ToFile:   "Copied",
			ToDate:   "",
			Context:  3,
		}
		diffText, _ := difflib.GetUnifiedDiffString(diff)

		t.Fatalf("Copied value is not deeply equal to the orginal:\n%v",
			diffText)
	}

	if originalVal.Kind() == reflect.Ptr {
		originalVal = originalVal.Elem()
		copiedVal = copiedVal.Elem()
	}

	for i := range originalVal.NumField() {
		f1 := originalVal.Field(i)
		f2 := copiedVal.Field(i)
		name := originalVal.Type().Field(i).Name

		checkAliasing(t, debug, strict, f1, f2, name)
	}
}
