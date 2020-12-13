package main

import (
	"github.com/hillu/go-yara/v4"

	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

func printMatches(item string, m []yara.MatchRule, err error) {
	if err != nil {
		log.Printf("%s: error: %s", item, err)
		return
	}
	if len(m) == 0 {
		log.Printf("%s: no matches", item)
		return
	}
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "%s: [", item)
	for i, match := range m {
		if i > 0 {
			fmt.Fprint(buf, ", ")
		}
		fmt.Fprintf(buf, "%s:%s", match.Namespace, match.Rule)
	}
	fmt.Fprint(buf, "]")
	log.Print(buf.String())
}

func main() {
	var (
		rules       rules
		vars        variables
		processScan bool
		pids        []int
		threads     int
	)
	flag.BoolVar(&processScan, "processes", false, "scan processes instead of files")
	flag.Var(&rules, "rule", "add rules in source form: [namespace:]filename")
	flag.Var(&vars, "define", "define variable referenced n ruleset")
	flag.IntVar(&threads, "threads", 1, "use specified number of threads")
	flag.Parse()

	if len(rules) == 0 {
		flag.Usage()
		log.Fatal("no rules specified")
	}

	args := flag.Args()
	if len(args) == 0 {
		flag.Usage()
		log.Fatal("no files or processes specified")
	}

	if processScan {
		for _, arg := range args {
			if pid, err := strconv.Atoi(arg); err != nil {
				log.Fatalf("Could not parse %s ad number", arg)
			} else {
				pids = append(pids, pid)
			}
		}
	}

	c, err := yara.NewCompiler()
	if err != nil {
		log.Fatalf("Failed to initialize YARA compiler: %s", err)
	}
	for id, value := range vars {
		if err := c.DefineVariable(id, value); err != nil {
			log.Fatal("failed to define variable '%s': %s", id, err)
		}
	}
	for _, rule := range rules {
		f, err := os.Open(rule.filename)
		if err != nil {
			log.Fatalf("Could not open rule file %s: %s", rule.filename, err)
		}
		err = c.AddFile(f, rule.namespace)
		f.Close()
		if err != nil {
			log.Fatalf("Could not parse rule file %s: %s", rule.filename, err)
		}
	}
	r, err := c.GetRules()
	if err != nil {
		log.Fatalf("Failed to compile rules: %s", err)
	}

	wg := sync.WaitGroup{}
	wg.Add(threads)

	if processScan {
		c := make(chan int, threads)
		for i := 0; i < threads; i++ {
			s, _ := yara.NewScanner(r)
			go func(c chan int, tid int) {
				for pid := range c {
					var m yara.MatchRules
					log.Printf("<%02d> Scanning process %d...", tid, pid)
					err := s.SetCallback(&m).ScanProc(pid)
					printMatches(fmt.Sprintf("<pid %d", pid), m, err)
				}
				wg.Done()
			}(c, i)
		}
		for _, pid := range pids {
			c <- pid
		}
		close(c)
	} else {
		c := make(chan string, threads)
		for i := 0; i < threads; i++ {
			s, _ := yara.NewScanner(r)
			go func(c chan string, tid int) {
				for filename := range c {
					var m yara.MatchRules
					log.Printf("<%02d> Scanning file %s... ", tid, filename)
					err := s.SetCallback(&m).ScanFile(filename)
					printMatches(filename, m, err)
				}
				wg.Done()
			}(c, i)
		}
		for _, path := range args {
			if err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
				if info.Mode().IsRegular() {
					c <- path
				} else if info.Mode().IsDir() {
					return nil
				} else {
					log.Printf("Sipping %s", path)
				}
				return nil
			}); err != nil {
				log.Printf("walk: %s: %s", path, err)
			}
		}
		close(c)
	}
	wg.Wait()
}
