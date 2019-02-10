package main

import (
	"flag"
	"fmt"
	"go/ast"
	"log"
	"os"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/tools/go/packages"
)

// Command line API:
// $ fizz
// fuzz in the current package
// $ fizz [pkgs]
// fuzz pkgs, defaults to current package
// $ fizz -c <pkgs>
// build a standalone binary
// $ fizz -fuzz=ABC [pkgs]
// run only fuzzers matching regexp ABC
// other things: rmcrashers, mkdir-only, set time limit on fuzzing, set number of workers, autogenerate fuzz functions
// -tags <list of tags>
// flagTag  = flag.String("tags", "", "a space-separated list of build tags to consider satisfied during the build")

var (
	flagTags = flag.String("tags", "", "a space-separated list of build tags to consider satisfied during the build")
	flagC    = flag.Bool("c", false, "compile the fuzz binary to pkg.fuzz but do not run it")
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("fizz: ")

	// flag munging
	flag.Parse()

	tags := "gofuzz"
	if *flagTags != "" {
		tags += " " + *flagTags
	}

	// Many tools pass their command-line arguments (after any flags)
	// uninterpreted to packages.Load so that it can interpret them
	// according to the conventions of the underlying build system.
	cfg := &packages.Config{
		Mode:       packages.LoadSyntax,
		BuildFlags: []string{"-tags", tags},
	}
	pkgs, err := packages.Load(cfg, flag.Args()...)
	if err != nil {
		log.Fatal(err)
	}

	if len(pkgs) > 1 && *flagC {
		// TODO: make this work!
		log.Fatalf("cannot use -c flag with multiple packages")
	}

	if packages.PrintErrors(pkgs) > 0 {
		// TODO: check IllTyped?
		os.Exit(1)
	}

	// Find all fuzz functions along with their containing packages.
	// Print the names of the source files
	// for each package listed on the command line.
	fns, err := findFuzzFuncs(pkgs)
	if err != nil {
		log.Fatal(err)
	}
	for _, fn := range fns {
		// fmt.Println(pkg.ID, pkg.GoFiles)
		fmt.Println(fn.pkg.ID, fn.name)
	}
}

type fuzzFunc struct {
	pkg  *packages.Package
	name string
}

func findFuzzFuncs(pkgs []*packages.Package) (fns []fuzzFunc, err error) {
	for _, pkg := range pkgs {
		for _, f := range pkg.Syntax {
			// f is an *ast.File
			for _, d := range f.Decls {
				fn, ok := d.(*ast.FuncDecl)
				if !ok {
					continue
				}
				name := fn.Name.String()
				if !isTest(name, "Fuzz") {
					continue
				}
				if !isTestFunc(fn, "F") {
					// similar to checkTestFunc from cmd/go/internal/load/test.go
					pos := pkg.Fset.Position(fn.Pos())
					return nil, fmt.Errorf("%s: wrong signature for %s, must be: func %s(f *fizz.F)", pos, name, name)
				}
				fns = append(fns, fuzzFunc{pkg: pkg, name: name})
			}
		}
	}
	return fns, nil
}

// isTest and isTestFunc were copied verbatim from cmd/go/internal/load/test.go

// isTest tells whether name looks like a test (or benchmark, according to prefix).
// It is a Test (say) if there is a character after Test that is not a lower-case letter.
// We don't want TesticularCancer.
func isTest(name, prefix string) bool {
	if !strings.HasPrefix(name, prefix) {
		return false
	}
	if len(name) == len(prefix) { // "Test" is ok
		return true
	}
	rune, _ := utf8.DecodeRuneInString(name[len(prefix):])
	return !unicode.IsLower(rune)
}

// isTestFunc tells whether fn has the type of a testing function. arg
// specifies the parameter type we look for: B, M or T.
func isTestFunc(fn *ast.FuncDecl, arg string) bool {
	if fn.Type.Results != nil && len(fn.Type.Results.List) > 0 ||
		fn.Type.Params.List == nil ||
		len(fn.Type.Params.List) != 1 ||
		len(fn.Type.Params.List[0].Names) > 1 {
		return false
	}
	ptr, ok := fn.Type.Params.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	// We can't easily check that the type is *testing.M
	// because we don't know how testing has been imported,
	// but at least check that it's *M or *something.M.
	// Same applies for B and T.
	if name, ok := ptr.X.(*ast.Ident); ok && name.Name == arg {
		return true
	}
	if sel, ok := ptr.X.(*ast.SelectorExpr); ok && sel.Sel.Name == arg {
		return true
	}
	return false
}
