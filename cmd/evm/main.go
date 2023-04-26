// Copyright 2014 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

// evm executes EVM code snippets.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"os"
	goruntime "runtime"
	"runtime/pprof"
	"testing"
	"time"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"github.com/sachindigi195/go-eth-evm/cmd/evm/internal/compiler"
	"github.com/sachindigi195/go-eth-evm/cmd/utils"
	"github.com/sachindigi195/go-eth-evm/common"
	"github.com/sachindigi195/go-eth-evm/core"
	"github.com/sachindigi195/go-eth-evm/core/rawdb"
	"github.com/sachindigi195/go-eth-evm/core/state"
	"github.com/sachindigi195/go-eth-evm/core/vm"
	"github.com/sachindigi195/go-eth-evm/core/vm/runtime"
	"github.com/sachindigi195/go-eth-evm/eth/tracers/logger"
	"github.com/sachindigi195/go-eth-evm/internal/flags"
	"github.com/sachindigi195/go-eth-evm/log"
	"github.com/sachindigi195/go-eth-evm/params"
	"github.com/sachindigi195/go-eth-evm/trie"
	"github.com/sachindigi195/go-eth-evm/core/asm"
	"github.com/sachindigi195/go-eth-evm/cmd/evm/internal/t8ntool"
	"github.com/sachindigi195/go-eth-evm/internal/flags"
	"github.com/urfave/cli/v2"
)

var (
	DebugFlag = &cli.BoolFlag{
		Name:  "debug",
		Usage: "output full trace logs",
	}
	MemProfileFlag = &cli.StringFlag{
		Name:  "memprofile",
		Usage: "creates a memory profile at the given path",
	}
	CPUProfileFlag = &cli.StringFlag{
		Name:  "cpuprofile",
		Usage: "creates a CPU profile at the given path",
	}
	StatDumpFlag = &cli.BoolFlag{
		Name:  "statdump",
		Usage: "displays stack and heap memory information",
	}
	CodeFlag = &cli.StringFlag{
		Name:  "code",
		Usage: "EVM code",
	}
	CodeFileFlag = &cli.StringFlag{
		Name:  "codefile",
		Usage: "File containing EVM code. If '-' is specified, code is read from stdin ",
	}
	GasFlag = &cli.Uint64Flag{
		Name:  "gas",
		Usage: "gas limit for the evm",
		Value: 10000000000,
	}
	PriceFlag = &flags.BigFlag{
		Name:  "price",
		Usage: "price set for the evm",
		Value: new(big.Int),
	}
	ValueFlag = &flags.BigFlag{
		Name:  "value",
		Usage: "value set for the evm",
		Value: new(big.Int),
	}
	DumpFlag = &cli.BoolFlag{
		Name:  "dump",
		Usage: "dumps the state after the run",
	}
	InputFlag = &cli.StringFlag{
		Name:  "input",
		Usage: "input for the EVM",
	}
	InputFileFlag = &cli.StringFlag{
		Name:  "inputfile",
		Usage: "file containing input for the EVM",
	}
	VerbosityFlag = &cli.IntFlag{
		Name:  "verbosity",
		Usage: "sets the verbosity level",
	}
	BenchFlag = &cli.BoolFlag{
		Name:  "bench",
		Usage: "benchmark the execution",
	}
	CreateFlag = &cli.BoolFlag{
		Name:  "create",
		Usage: "indicates the action should be create rather than call",
	}
	GenesisFlag = &cli.StringFlag{
		Name:  "prestate",
		Usage: "JSON file with prestate (genesis) config",
	}
	MachineFlag = &cli.BoolFlag{
		Name:  "json",
		Usage: "output trace logs in machine readable format (json)",
	}
	SenderFlag = &cli.StringFlag{
		Name:  "sender",
		Usage: "The transaction origin",
	}
	ReceiverFlag = &cli.StringFlag{
		Name:  "receiver",
		Usage: "The transaction receiver (execution context)",
	}
	DisableMemoryFlag = &cli.BoolFlag{
		Name:  "nomemory",
		Value: true,
		Usage: "disable memory output",
	}
	DisableStackFlag = &cli.BoolFlag{
		Name:  "nostack",
		Usage: "disable stack output",
	}
	DisableStorageFlag = &cli.BoolFlag{
		Name:  "nostorage",
		Usage: "disable storage output",
	}
	DisableReturnDataFlag = &cli.BoolFlag{
		Name:  "noreturndata",
		Value: true,
		Usage: "enable return data output",
	}
)

var stateTransitionCommand = &cli.Command{
	Name:    "transition",
	Aliases: []string{"t8n"},
	Usage:   "executes a full state transition",
	Action:  t8ntool.Transition,
	Flags: []cli.Flag{
		t8ntool.TraceFlag,
		t8ntool.TraceDisableMemoryFlag,
		t8ntool.TraceEnableMemoryFlag,
		t8ntool.TraceDisableStackFlag,
		t8ntool.TraceDisableReturnDataFlag,
		t8ntool.TraceEnableReturnDataFlag,
		t8ntool.OutputBasedir,
		t8ntool.OutputAllocFlag,
		t8ntool.OutputResultFlag,
		t8ntool.OutputBodyFlag,
		t8ntool.InputAllocFlag,
		t8ntool.InputEnvFlag,
		t8ntool.InputTxsFlag,
		t8ntool.ForknameFlag,
		t8ntool.ChainIDFlag,
		t8ntool.RewardFlag,
		t8ntool.VerbosityFlag,
	},
}

var transactionCommand = &cli.Command{
	Name:    "transaction",
	Aliases: []string{"t9n"},
	Usage:   "performs transaction validation",
	Action:  t8ntool.Transaction,
	Flags: []cli.Flag{
		t8ntool.InputTxsFlag,
		t8ntool.ChainIDFlag,
		t8ntool.ForknameFlag,
		t8ntool.VerbosityFlag,
	},
}

var compileCommand = &cli.Command{
	Action:    compileCmd,
	Name:      "compile",
	Usage:     "compiles easm source to evm binary",
	ArgsUsage: "<file>",
}

var disasmCommand = &cli.Command{
	Action:    disasmCmd,
	Name:      "disasm",
	Usage:     "disassembles evm binary",
	ArgsUsage: "<file>",
}

var runCommand = &cli.Command{
	Action:      runCmd,
	Name:        "run",
	Usage:       "run arbitrary evm binary",
	ArgsUsage:   "<code>",
	Description: `The run command runs arbitrary EVM code.`,
}

var blockTestCommand = &cli.Command{
	Action:    compileCmd,
	Name:      "compile",
	Usage:     "compiles easm source to evm binary",
	ArgsUsage: "<file>",
}

var stateTestCommand = &cli.Command{
	Action:    compileCmd,
	Name:      "compile",
	Usage:     "compiles easm source to evm binary",
	ArgsUsage: "<file>",
}

var blockBuilderCommand = &cli.Command{
	Name:    "block-builder",
	Aliases: []string{"b11r"},
	Usage:   "builds a block",
	Action:  t8ntool.BuildBlock,
	Flags: []cli.Flag{
		t8ntool.OutputBasedir,
		t8ntool.OutputBlockFlag,
		t8ntool.InputHeaderFlag,
		t8ntool.InputOmmersFlag,
		t8ntool.InputWithdrawalsFlag,
		t8ntool.InputTxsRlpFlag,
		t8ntool.SealCliqueFlag,
		t8ntool.SealEthashFlag,
		t8ntool.SealEthashDirFlag,
		t8ntool.SealEthashModeFlag,
		t8ntool.VerbosityFlag,
	},
}

var app = flags.NewApp("the evm command line interface")

func init() {
	app.Flags = []cli.Flag{
		BenchFlag,
		CreateFlag,
		DebugFlag,
		VerbosityFlag,
		CodeFlag,
		CodeFileFlag,
		GasFlag,
		PriceFlag,
		ValueFlag,
		DumpFlag,
		InputFlag,
		InputFileFlag,
		MemProfileFlag,
		CPUProfileFlag,
		StatDumpFlag,
		GenesisFlag,
		MachineFlag,
		SenderFlag,
		ReceiverFlag,
		DisableMemoryFlag,
		DisableStackFlag,
		DisableStorageFlag,
		DisableReturnDataFlag,
	}
	app.Commands = []*cli.Command{
		compileCommand,
		disasmCommand,
		runCommand,
		blockTestCommand,
		stateTestCommand,
		stateTransitionCommand,
		transactionCommand,
		blockBuilderCommand,
	}
}

func main() {
	if err := app.Run(os.Args); err != nil {
		code := 1
		if ec, ok := err.(*t8ntool.NumberedError); ok {
			code = ec.ExitCode()
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(code)
	}
}


func compileCmd(ctx *cli.Context) error {
	debug := ctx.Bool(DebugFlag.Name)

	if len(ctx.Args().First()) == 0 {
		return errors.New("filename required")
	}

	fn := ctx.Args().First()
	src, err := os.ReadFile(fn)
	if err != nil {
		return err
	}

	bin, err := compiler.Compile(fn, src, debug)
	if err != nil {
		return err
	}
	fmt.Println(bin)
	return nil
}

func disasmCmd(ctx *cli.Context) error {
	var in string
	switch {
	case len(ctx.Args().First()) > 0:
		fn := ctx.Args().First()
		input, err := os.ReadFile(fn)
		if err != nil {
			return err
		}
		in = string(input)
	case ctx.IsSet(InputFlag.Name):
		in = ctx.String(InputFlag.Name)
	default:
		return errors.New("missing filename or --input value")
	}

	code := strings.TrimSpace(in)
	fmt.Printf("%v\n", code)
	return asm.PrintDisassembled(code)
}




// readGenesis will read the given JSON format genesis file and return
// the initialized Genesis structure
func readGenesis(genesisPath string) *core.Genesis {
	// Make sure we have a valid genesis JSON
	//genesisPath := ctx.Args().First()
	if len(genesisPath) == 0 {
		utils.Fatalf("Must supply path to genesis JSON file")
	}
	file, err := os.Open(genesisPath)
	if err != nil {
		utils.Fatalf("Failed to read genesis file: %v", err)
	}
	defer file.Close()

	genesis := new(core.Genesis)
	if err := json.NewDecoder(file).Decode(genesis); err != nil {
		utils.Fatalf("invalid genesis file: %v", err)
	}
	return genesis
}

type execStats struct {
	time           time.Duration // The execution time.
	allocs         int64         // The number of heap allocations during execution.
	bytesAllocated int64         // The cumulative number of bytes allocated during execution.
}

func timedExec(bench bool, execFunc func() ([]byte, uint64, error)) (output []byte, gasLeft uint64, stats execStats, err error) {
	if bench {
		result := testing.Benchmark(func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				output, gasLeft, err = execFunc()
			}
		})

		// Get the average execution time from the benchmarking result.
		// There are other useful stats here that could be reported.
		stats.time = time.Duration(result.NsPerOp())
		stats.allocs = result.AllocsPerOp()
		stats.bytesAllocated = result.AllocedBytesPerOp()
	} else {
		var memStatsBefore, memStatsAfter goruntime.MemStats
		goruntime.ReadMemStats(&memStatsBefore)
		startTime := time.Now()
		output, gasLeft, err = execFunc()
		stats.time = time.Since(startTime)
		goruntime.ReadMemStats(&memStatsAfter)
		stats.allocs = int64(memStatsAfter.Mallocs - memStatsBefore.Mallocs)
		stats.bytesAllocated = int64(memStatsAfter.TotalAlloc - memStatsBefore.TotalAlloc)
	}

	return output, gasLeft, stats, err
}

func runCmd(ctx *cli.Context) error {
	glogger := log.NewGlogHandler(log.StreamHandler(os.Stderr, log.TerminalFormat(false)))
	glogger.Verbosity(log.Lvl(ctx.Int(VerbosityFlag.Name)))
	log.Root().SetHandler(glogger)
	logconfig := &logger.Config{
		EnableMemory:     !ctx.Bool(DisableMemoryFlag.Name),
		DisableStack:     ctx.Bool(DisableStackFlag.Name),
		DisableStorage:   ctx.Bool(DisableStorageFlag.Name),
		EnableReturnData: !ctx.Bool(DisableReturnDataFlag.Name),
		Debug:            ctx.Bool(DebugFlag.Name),
	}

	var (
		tracer        vm.EVMLogger
		debugLogger   *logger.StructLogger
		statedb       *state.StateDB
		chainConfig   *params.ChainConfig
		sender        = common.BytesToAddress([]byte("sender"))
		receiver      = common.BytesToAddress([]byte("receiver"))
		genesisConfig *core.Genesis
		preimages     = ctx.Bool(DumpFlag.Name)
	)
	if ctx.Bool(MachineFlag.Name) {
		tracer = logger.NewJSONLogger(logconfig, os.Stdout)
	} else if ctx.Bool(DebugFlag.Name) {
		debugLogger = logger.NewStructLogger(logconfig)
		tracer = debugLogger
	} else {
		debugLogger = logger.NewStructLogger(logconfig)
	}
	if ctx.String(GenesisFlag.Name) != "" {
		gen := readGenesis(ctx.String(GenesisFlag.Name))
		genesisConfig = gen
		db := rawdb.NewMemoryDatabase()
		genesis := gen.MustCommit(db)
		sdb := state.NewDatabaseWithConfig(db, &trie.Config{Preimages: preimages})
		statedb, _ = state.New(genesis.Root(), sdb, nil)
		chainConfig = gen.Config
	} else {
		sdb := state.NewDatabaseWithConfig(rawdb.NewMemoryDatabase(), &trie.Config{Preimages: preimages})
		statedb, _ = state.New(common.Hash{}, sdb, nil)
		genesisConfig = new(core.Genesis)
	}
	if ctx.String(SenderFlag.Name) != "" {
		sender = common.HexToAddress(ctx.String(SenderFlag.Name))
	}
	statedb.CreateAccount(sender)

	if ctx.String(ReceiverFlag.Name) != "" {
		receiver = common.HexToAddress(ctx.String(ReceiverFlag.Name))
	}

	var code []byte
	codeFileFlag := ctx.String(CodeFileFlag.Name)
	codeFlag := ctx.String(CodeFlag.Name)

	// The '--code' or '--codefile' flag overrides code in state
	if codeFileFlag != "" || codeFlag != "" {
		var hexcode []byte
		if codeFileFlag != "" {
			var err error
			// If - is specified, it means that code comes from stdin
			if codeFileFlag == "-" {
				//Try reading from stdin
				if hexcode, err = io.ReadAll(os.Stdin); err != nil {
					fmt.Printf("Could not load code from stdin: %v\n", err)
					os.Exit(1)
				}
			} else {
				// Codefile with hex assembly
				if hexcode, err = os.ReadFile(codeFileFlag); err != nil {
					fmt.Printf("Could not load code from file: %v\n", err)
					os.Exit(1)
				}
			}
		} else {
			hexcode = []byte(codeFlag)
		}
		hexcode = bytes.TrimSpace(hexcode)
		if len(hexcode)%2 != 0 {
			fmt.Printf("Invalid input length for hex data (%d)\n", len(hexcode))
			os.Exit(1)
		}
		code = common.FromHex(string(hexcode))
	} else if fn := ctx.Args().First(); len(fn) > 0 {
		// EASM-file to compile
		src, err := os.ReadFile(fn)
		if err != nil {
			return err
		}
		bin, err := compiler.Compile(fn, src, false)
		if err != nil {
			return err
		}
		code = common.Hex2Bytes(bin)
	}
	initialGas := ctx.Uint64(GasFlag.Name)
	if genesisConfig.GasLimit != 0 {
		initialGas = genesisConfig.GasLimit
	}
	runtimeConfig := runtime.Config{
		Origin:      sender,
		State:       statedb,
		GasLimit:    initialGas,
		GasPrice:    flags.GlobalBig(ctx, PriceFlag.Name),
		Value:       flags.GlobalBig(ctx, ValueFlag.Name),
		Difficulty:  genesisConfig.Difficulty,
		Time:        genesisConfig.Timestamp,
		Coinbase:    genesisConfig.Coinbase,
		BlockNumber: new(big.Int).SetUint64(genesisConfig.Number),
		EVMConfig: vm.Config{
			Tracer: tracer,
		},
	}

	if cpuProfilePath := ctx.String(CPUProfileFlag.Name); cpuProfilePath != "" {
		f, err := os.Create(cpuProfilePath)
		if err != nil {
			fmt.Println("could not create CPU profile: ", err)
			os.Exit(1)
		}
		if err := pprof.StartCPUProfile(f); err != nil {
			fmt.Println("could not start CPU profile: ", err)
			os.Exit(1)
		}
		defer pprof.StopCPUProfile()
	}

	if chainConfig != nil {
		runtimeConfig.ChainConfig = chainConfig
	} else {
		runtimeConfig.ChainConfig = params.AllEthashProtocolChanges
	}

	var hexInput []byte
	if inputFileFlag := ctx.String(InputFileFlag.Name); inputFileFlag != "" {
		var err error
		if hexInput, err = os.ReadFile(inputFileFlag); err != nil {
			fmt.Printf("could not load input from file: %v\n", err)
			os.Exit(1)
		}
	} else {
		hexInput = []byte(ctx.String(InputFlag.Name))
	}
	hexInput = bytes.TrimSpace(hexInput)
	if len(hexInput)%2 != 0 {
		fmt.Println("input length must be even")
		os.Exit(1)
	}
	input := common.FromHex(string(hexInput))

	var execFunc func() ([]byte, uint64, error)
	if ctx.Bool(CreateFlag.Name) {
		input = append(code, input...)
		execFunc = func() ([]byte, uint64, error) {
			output, _, gasLeft, err := runtime.Create(input, &runtimeConfig)
			return output, gasLeft, err
		}
	} else {
		if len(code) > 0 {
			statedb.SetCode(receiver, code)
		}
		execFunc = func() ([]byte, uint64, error) {
			return runtime.Call(receiver, input, &runtimeConfig)
		}
	}

	bench := ctx.Bool(BenchFlag.Name)
	output, leftOverGas, stats, err := timedExec(bench, execFunc)

	if ctx.Bool(DumpFlag.Name) {
		statedb.Commit(true)
		statedb.IntermediateRoot(true)
		fmt.Println(string(statedb.Dump(nil)))
	}

	if memProfilePath := ctx.String(MemProfileFlag.Name); memProfilePath != "" {
		f, err := os.Create(memProfilePath)
		if err != nil {
			fmt.Println("could not create memory profile: ", err)
			os.Exit(1)
		}
		if err := pprof.WriteHeapProfile(f); err != nil {
			fmt.Println("could not write memory profile: ", err)
			os.Exit(1)
		}
		f.Close()
	}

	if ctx.Bool(DebugFlag.Name) {
		if debugLogger != nil {
			fmt.Fprintln(os.Stderr, "#### TRACE ####")
			logger.WriteTrace(os.Stderr, debugLogger.StructLogs())
		}
		fmt.Fprintln(os.Stderr, "#### LOGS ####")
		logger.WriteLogs(os.Stderr, statedb.Logs())
	}

	if bench || ctx.Bool(StatDumpFlag.Name) {
		fmt.Fprintf(os.Stderr, `EVM gas used:    %d
execution time:  %v
allocations:     %d
allocated bytes: %d
`, initialGas-leftOverGas, stats.time, stats.allocs, stats.bytesAllocated)
	}
	if tracer == nil {
		fmt.Printf("%#x\n", output)
		if err != nil {
			fmt.Printf(" error: %v\n", err)
		}
	}

	return nil
}
