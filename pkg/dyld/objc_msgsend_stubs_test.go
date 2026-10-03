package dyld

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"

	mtypes "github.com/blacktop/go-macho/types"
)

// Three layers, none needs a real cache:
//   - instruction encoders: decodeObjcMsgSendStub on synthetic addresses (any layout)
//   - testdata/fixtures/objc_msgsend_stubs_26A434.json: real bytes from one macOS 27 cache, with selectors
//     taken from the official ipsw disassembly, decoded and compared
//   - a synthetic in-memory cache built from that fixture: regions, lookups, full scan, callers
//     (and, under "error and boundary cases" below, the same cache changed into layouts that have no
//     stubs, which is not an error, or that this code cannot trust, which is an error everywhere)
// TestObjcMsgSendStubsRealCache additionally runs on a whole cache when DSC is set.

// ARM64 encoders for the four stub instructions (and BL for callers).
func encADRP(rd uint32, pc, target uint64) uint32 {
	imm := uint32((int64(target&^0xfff) - int64(pc&^0xfff)) >> 12)
	return 0x90000000 | (imm&0x3)<<29 | (imm>>2&0x7ffff)<<5 | rd
}
func encADD(rd, rn, imm12 uint32, lsl12 bool) uint32 {
	insn := 0x91000000 | imm12<<10 | rn<<5 | rd
	if lsl12 {
		insn |= 1 << 22
	}
	return insn
}
func encLDR(rt, rn, byteOff uint32) uint32 { return 0xf9400000 | (byteOff/8)<<10 | rn<<5 | rt }
func encB(pc, target uint64) uint32 {
	return 0x14000000 | uint32((int64(target)-int64(pc))/4)&0x03ffffff
}
func encBL(pc, target uint64) uint32 {
	return 0x94000000 | uint32((int64(target)-int64(pc))/4)&0x03ffffff
}

// stub encodes the 16-byte selector stub at pc for the selector string at sel.
func stub(pc, sel, msgSend uint64) [4]uint32 {
	return [4]uint32{encADRP(1, pc, sel), encADD(1, 1, uint32(sel&0xfff), false), encB(pc+8, msgSend), arm64InsnBrk1}
}

func TestDecodeObjcMsgSendStub(t *testing.T) {
	// A layout unlike any real cache: __TEXT at 0x10000, objc_msgSend at +0x800, stubs below and
	// above it, selector strings both above and below the stubs (negative ADRP).
	const msgSend = 0x10800
	ldr := stub(0x20000, 0x7000, msgSend)
	ldr[1] = encLDR(1, 1, 0x18)
	lsl := stub(0x20000, 0x3000000, msgSend)
	lsl[1] = encADD(1, 1, 0x5, true)
	toSuper := stub(0x20000, 0x7000, msgSend)
	toSuper[2] = encB(0x20008, msgSend+0x220)
	asBL := stub(0x20000, 0x7000, msgSend)
	asBL[2] = encBL(0x20008, msgSend)
	x2 := stub(0x20000, 0x7000, msgSend)
	x2[0] = encADRP(2, 0x20000, 0x7000)
	noBrk := stub(0x20000, 0x7000, msgSend)
	noBrk[3] = 0xd503201f // nop

	tests := []struct {
		name     string
		pc       uint64
		insns    [4]uint32
		wantAddr uint64
		wantOK   bool
	}{
		{name: "selector above the stub", pc: 0x20000, insns: stub(0x20000, 0x5123456, msgSend), wantAddr: 0x5123456, wantOK: true},
		{name: "selector below the stub (negative adrp)", pc: 0x8000000, insns: stub(0x8000000, 0x7abc, msgSend), wantAddr: 0x7abc, wantOK: true},
		{name: "stub below objc_msgSend (forward branch)", pc: 0x400, insns: stub(0x400, 0x9000, msgSend), wantAddr: 0x9000, wantOK: true},
		{name: "add with LSL #12", pc: 0x20000, insns: lsl, wantAddr: 0x3005000, wantOK: true},
		{name: "ldr form (selector reference) is not decoded", pc: 0x20000, insns: ldr},
		{name: "branch to another entry point", pc: 0x20000, insns: toSuper},
		{name: "bl instead of b", pc: 0x20000, insns: asBL},
		{name: "adrp into x2", pc: 0x20000, insns: x2},
		{name: "no brk #1", pc: 0x20000, insns: noBrk},
		{name: "zero padding", pc: 0x20000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, ok := decodeObjcMsgSendStub(tt.insns, tt.pc, msgSend)
			if ok != tt.wantOK || addr != tt.wantAddr {
				t.Fatalf("decode = (%#x, %v), want (%#x, %v)", addr, ok, tt.wantAddr, tt.wantOK)
			}
		})
	}
}

func TestObjcMsgSendStubNames(t *testing.T) {
	s := ObjcMsgSendStub{Selector: "initWithQueue:"}
	if got, want := s.SymbolName(), `j__objc_msgSend(x0, "initWithQueue:")`; got != want {
		t.Fatalf("SymbolName() = %q, want %q", got, want)
	}
	if got, want := s.LinkerName(), "_objc_msgSend$initWithQueue:"; got != want {
		t.Fatalf("LinkerName() = %q, want %q", got, want)
	}
}

func TestObjcMsgSendImageName(t *testing.T) {
	for name, want := range map[string]bool{
		"/usr/lib/objc/libobjcMsgSend.dylib":   true,
		"/usr/lib/objc/libobjcMsgSend33.dylib": true,
		"/usr/lib/libobjc.A.dylib":             false,
		"/usr/lib/objc/libobjcMsgSendX.dylib":  false,
	} {
		if got := objcMsgSendImageRE.MatchString(name); got != want {
			t.Errorf("%s: match = %v, want %v", name, got, want)
		}
	}
}

// --- fixture -----------------------------------------------------------------------------

type stubFixture struct {
	Source      string `json:"source"`
	Image       string `json:"image"`
	TextStart   string `json:"text_start"`
	TextEnd     string `json:"text_end"`
	ObjcMsgSend string `json:"objc_msgSend"`
	MappingEnd  string `json:"mapping_end"`
	Chunks      []struct {
		Addr string `json:"addr"`
		Hex  string `json:"hex"`
	} `json:"chunks"`
	Stubs []struct {
		Addr         string `json:"addr"`
		SelectorAddr string `json:"selector_addr"`
		Selector     string `json:"selector"`
	} `json:"stubs"`
}

func hexAddr(t *testing.T, s string) uint64 {
	t.Helper()
	v, err := strconv.ParseUint(s, 0, 64)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func loadStubFixture(t *testing.T) *stubFixture {
	t.Helper()
	data, err := os.ReadFile("testdata/fixtures/objc_msgsend_stubs_26A434.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx stubFixture
	if err := json.Unmarshal(data, &fx); err != nil {
		t.Fatal(err)
	}
	return &fx
}

// chunkWords returns the instruction words of every fixture chunk keyed by address.
func (fx *stubFixture) words(t *testing.T) map[uint64]uint32 {
	words := map[uint64]uint32{}
	for _, c := range fx.Chunks {
		b, err := hex.DecodeString(c.Hex)
		if err != nil {
			t.Fatal(err)
		}
		base := hexAddr(t, c.Addr)
		for i := 0; i+4 <= len(b); i += 4 {
			words[base+uint64(i)] = binary.LittleEndian.Uint32(b[i:])
		}
	}
	return words
}

// Real stub bytes decode to the selector the official ipsw disassembly names for them.
func TestDecodeObjcMsgSendStubFixture(t *testing.T) {
	fx := loadStubFixture(t)
	words := fx.words(t)
	msgSend := hexAddr(t, fx.ObjcMsgSend)
	want := map[uint64]uint64{}
	for _, s := range fx.Stubs {
		want[hexAddr(t, s.Addr)] = hexAddr(t, s.SelectorAddr)
	}
	decoded := 0
	for pc := range words {
		insns := [4]uint32{words[pc], words[pc+4], words[pc+8], words[pc+12]}
		sel, ok := decodeObjcMsgSendStub(insns, pc, msgSend)
		if wantSel, isStub := want[pc]; isStub {
			if !ok || sel != wantSel {
				t.Errorf("%#x: decode = (%#x, %v), want %#x", pc, sel, ok, wantSel)
			}
			decoded++
		} else if ok {
			t.Errorf("%#x: decoded a stub where the fixture has none", pc)
		}
	}
	if decoded != len(fx.Stubs) {
		t.Fatalf("decoded %d of %d fixture stubs", decoded, len(fx.Stubs))
	}
}

// --- synthetic cache -----------------------------------------------------------------------

// sparseReader serves zeros except at the given offsets.
type sparseReader map[int64][]byte

func (s sparseReader) ReadAt(p []byte, off int64) (int, error) {
	clear(p)
	for at, b := range s {
		lo, hi := max(at, off), min(at+int64(len(b)), off+int64(len(p)))
		if lo < hi {
			copy(p[lo-off:hi-off], b[lo-at:hi-at])
		}
	}
	return len(p), nil
}

const (
	synthCaller     = "/System/Library/Frameworks/Caller.framework/Caller"
	synthCallerBase = 0x187ff0000
	synthDataStart  = 0x1f4000000 // selector strings and the export trie
	synthDataSize   = 0x2000000
	synthDataFile   = 0x10000000 // file offset of the data mapping in the reader
	synthTrieAddr   = 0x1f5ff0000
)

// objcMsgSendTrie is an export trie with the single entry _objc_msgSend -> image+off.
func objcMsgSendTrie(off uint64) []byte {
	var leaf []byte
	leaf = binary.AppendUvarint(leaf, 0) // flags
	leaf = binary.AppendUvarint(leaf, off)
	root := append([]byte{0, 1}, "_objc_msgSend\x00"...)
	root = append(root, byte(len(root)+1)) // child node right after the root
	node := append([]byte{byte(len(leaf))}, leaf...)
	return append(append(root, node...), 0) // no children
}

// synthCache builds a cache holding the fixture: a caller image, libobjcMsgSend.dylib with its
// stubs, a stub that branches to another __TEXT entry point, the selector strings, and an export
// trie for _objc_msgSend.
func synthCache(t *testing.T, fx *stubFixture) (*File, *CacheImage, *CacheImage) {
	t.Helper()
	textStart, textEnd := hexAddr(t, fx.TextStart), hexAddr(t, fx.TextEnd)
	msgSend, mappingEnd := hexAddr(t, fx.ObjcMsgSend), hexAddr(t, fx.MappingEnd)
	r := sparseReader{}
	code := func(addr uint64, b []byte) { r[int64(addr-synthCallerBase)] = b }
	data := func(addr uint64, b []byte) { r[int64(synthDataFile+addr-synthDataStart)] = b }

	for _, c := range fx.Chunks {
		b, err := hex.DecodeString(c.Hex)
		if err != nil {
			t.Fatal(err)
		}
		code(hexAddr(t, c.Addr), b)
	}
	for _, s := range fx.Stubs {
		data(hexAddr(t, s.SelectorAddr), append([]byte(s.Selector), 0))
	}
	// a stub-shaped group to objc_msgSendSuper2 (image+0xa20) in the zero gap: must not be named
	words := stub(0x188050000, hexAddr(t, fx.Stubs[0].SelectorAddr), textStart+0xa20)
	var super2 [16]byte
	for i, w := range words {
		binary.LittleEndian.PutUint32(super2[i*4:], w)
	}
	code(0x188050000, super2[:])
	// the caller: BL to a fixture stub, BL to objc_msgSend itself, BL to the Super2 group
	target := hexAddr(t, fx.Stubs[9].Addr)
	var caller [12]byte
	binary.LittleEndian.PutUint32(caller[0:], encBL(synthCallerBase, target))
	binary.LittleEndian.PutUint32(caller[4:], encBL(synthCallerBase+4, msgSend))
	binary.LittleEndian.PutUint32(caller[8:], encBL(synthCallerBase+8, 0x188050000))
	code(synthCallerBase, caller[:])
	trie := objcMsgSendTrie(msgSend - textStart)
	data(synthTrieAddr, trie)

	uuid := mtypes.UUID{1}
	f := &File{
		UUID:                  uuid,
		ByteOrder:             binary.LittleEndian,
		AddressToSymbol:       NewA2STable(0),
		r:                     map[mtypes.UUID]io.ReaderAt{uuid: r},
		Mappings:              map[mtypes.UUID]cacheMappings{},
		MappingsWithSlideInfo: map[mtypes.UUID]cacheMappingsWithSlideInfo{},
	}
	for _, m := range []CacheMappingInfo{
		{Address: synthCallerBase, Size: mappingEnd - synthCallerBase, FileOffset: 0},
		{Address: synthDataStart, Size: synthDataSize, FileOffset: synthDataFile},
	} {
		f.Mappings[uuid] = append(f.Mappings[uuid], &CacheMapping{CacheMappingInfo: m})
		f.MappingsWithSlideInfo[uuid] = append(f.MappingsWithSlideInfo[uuid], &CacheMappingWithSlideInfo{
			CacheMappingAndSlideInfo: CacheMappingAndSlideInfo{Address: m.Address, Size: m.Size, FileOffset: m.FileOffset},
		})
	}
	callerImg := &CacheImage{Name: synthCaller, cache: f, cuuid: uuid,
		CacheImageTextInfo: CacheImageTextInfo{LoadAddress: synthCallerBase, TextSegmentSize: uint32(len(caller))}}
	msgImg := &CacheImage{Name: fx.Image, cache: f, cuuid: uuid,
		CacheImageTextInfo:  CacheImageTextInfo{LoadAddress: textStart, TextSegmentSize: uint32(textEnd - textStart)},
		CacheImageInfoExtra: CacheImageInfoExtra{ExportsTrieAddr: synthTrieAddr, ExportsTrieSize: uint32(len(trie))}}
	f.Images = cacheImages{callerImg, msgImg}
	return f, callerImg, msgImg
}

func TestObjcMsgSendStubsSyntheticCache(t *testing.T) {
	fx := loadStubFixture(t)
	f, caller, msgImg := synthCache(t, fx)

	regions, err := f.objcMsgSendRegions()
	if err != nil {
		t.Fatal(err)
	}
	msgSend := hexAddr(t, fx.ObjcMsgSend)
	if len(regions) != 1 || regions[0].textEnd != hexAddr(t, fx.TextEnd) || regions[0].end != hexAddr(t, fx.MappingEnd) {
		t.Fatalf("regions = %+v", regions)
	}
	if regions[0].msgSend != msgSend {
		t.Fatalf("branch target %#x, want _objc_msgSend %#x from the export trie", regions[0].msgSend, msgSend)
	}

	stubs, err := f.GetObjcMsgSendStubs()
	if err != nil {
		t.Fatal(err)
	}
	if len(stubs) != len(fx.Stubs) {
		t.Fatalf("full scan found %d stubs, fixture has %d (Super2 group or zero gap decoded?)", len(stubs), len(fx.Stubs))
	}
	for _, s := range fx.Stubs {
		addr := hexAddr(t, s.Addr)
		if got := stubs[addr]; got.Selector != s.Selector || got.Image != msgImg {
			t.Errorf("scan %#x = %+v, want %q", addr, got, s.Selector)
		}
		if got, ok, err := f.LookupObjcMsgSendStub(addr); err != nil || !ok || got.Selector != s.Selector {
			t.Errorf("lookup %#x = (%+v, %v, %v), want %q", addr, got, ok, err, s.Selector)
		}
		if start, got, ok, err := f.ObjcMsgSendStubContaining(addr + 8); err != nil || !ok || start != addr || got.Selector != s.Selector {
			t.Errorf("containing %#x = (%#x, %+v, %v, %v), want start %#x", addr+8, start, got, ok, err, addr)
		}
		if _, ok, err := f.LookupObjcMsgSendStub(addr + 4); ok || err != nil {
			t.Errorf("lookup %#x (inside a stub) = (%v, %v), want no stub and no error", addr+4, ok, err)
		}
	}
	if _, ok, err := f.LookupObjcMsgSendStub(0x188050000); ok || err != nil {
		t.Errorf("a stub branching to objc_msgSendSuper2: (%v, %v), want no stub and no error", ok, err)
	}

	called, err := f.GetObjcMsgSendStubsCalledBy(caller)
	if err != nil {
		t.Fatal(err)
	}
	want := hexAddr(t, fx.Stubs[9].Addr)
	if len(called) != 1 || called[want].Selector != fx.Stubs[9].Selector {
		t.Fatalf("called by caller = %+v, want only %#x (%s)", called, want, fx.Stubs[9].Selector)
	}
}

// --- error and boundary cases ------------------------------------------------------------

func putCode(f *File, addr uint64, words ...uint32) {
	b := make([]byte, 4*len(words))
	for i, w := range words {
		binary.LittleEndian.PutUint32(b[i*4:], w)
	}
	f.r[f.UUID].(sparseReader)[int64(addr-synthCallerBase)] = b
}

func putData(f *File, addr uint64, b []byte) {
	f.r[f.UUID].(sparseReader)[int64(synthDataFile+addr-synthDataStart)] = b
}

func setFirstMappingEnd(f *File, end uint64) {
	f.Mappings[f.UUID][0].Size = end - synthCallerBase
	f.MappingsWithSlideInfo[f.UUID][0].Size = end - synthCallerBase
}

// noStub fails unless both lookups report addr as no stub, without an error.
func noStub(t *testing.T, f *File, addr uint64) {
	t.Helper()
	if s, ok, err := f.LookupObjcMsgSendStub(addr); ok || err != nil {
		t.Errorf("lookup %#x = (%+v, %v, %v), want no stub and no error", addr, s, ok, err)
	}
	if start, s, ok, err := f.ObjcMsgSendStubContaining(addr); ok || err != nil {
		t.Errorf("containing %#x = (%#x, %+v, %v, %v), want no stub and no error", addr, start, s, ok, err)
	}
}

// failsEverywhere fails unless every entry point returns an error containing want: a lookup at
// addr, the full scan, and the stubs called by caller.
func failsEverywhere(t *testing.T, f *File, caller *CacheImage, addr uint64, want string) {
	t.Helper()
	check := func(what string, err error) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want one containing %q", what, err, want)
		}
	}
	_, _, err := f.LookupObjcMsgSendStub(addr)
	check("lookup", err)
	_, _, _, err = f.ObjcMsgSendStubContaining(addr)
	check("containing", err)
	stubs, err := f.GetObjcMsgSendStubs()
	check("full scan", err)
	if stubs != nil {
		t.Errorf("full scan returned %d stubs along with the error", len(stubs))
	}
	called, err := f.GetObjcMsgSendStubsCalledBy(caller)
	check("called by", err)
	if called != nil {
		t.Errorf("called by returned %d stubs along with the error", len(called))
	}
}

// Layouts without stubs are not errors: no libobjcMsgSendN image (caches before 27), or less than
// one stub of room between __TEXT and the next image or the end of the mapping.
func TestObjcMsgSendStubsNoRange(t *testing.T) {
	fx := loadStubFixture(t)
	textEnd := hexAddr(t, fx.TextEnd)
	nextImage := func(at uint64) func(*File, *CacheImage) {
		return func(f *File, _ *CacheImage) {
			f.Images = append(f.Images, &CacheImage{Name: "/usr/lib/libNext.dylib", cache: f, cuuid: f.UUID,
				CacheImageTextInfo: CacheImageTextInfo{LoadAddress: at, TextSegmentSize: 0x1000}})
		}
	}
	for _, tt := range []struct {
		name   string
		change func(*File, *CacheImage)
	}{
		{"no libobjcMsgSendN image", func(_ *File, msgImg *CacheImage) { msgImg.Name = "/usr/lib/libobjc.A.dylib" }},
		{"next image right after __TEXT", nextImage(textEnd)},
		{"next image 12 bytes after __TEXT", nextImage(textEnd + 12)},
		{"mapping ends at the end of __TEXT", func(f *File, _ *CacheImage) { setFirstMappingEnd(f, textEnd) }},
		{"mapping ends 12 bytes after __TEXT", func(f *File, _ *CacheImage) { setFirstMappingEnd(f, textEnd+12) }},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f, caller, msgImg := synthCache(t, fx)
			tt.change(f, msgImg)
			if regions, err := f.objcMsgSendRegions(); err != nil || len(regions) != 0 {
				t.Fatalf("regions = (%+v, %v), want none and no error", regions, err)
			}
			if stubs, err := f.GetObjcMsgSendStubs(); err != nil || len(stubs) != 0 {
				t.Errorf("full scan = (%d stubs, %v), want none and no error", len(stubs), err)
			}
			if called, err := f.GetObjcMsgSendStubsCalledBy(caller); err != nil || len(called) != 0 {
				t.Errorf("called by = (%d stubs, %v), want none and no error", len(called), err)
			}
			noStub(t, f, hexAddr(t, fx.Stubs[0].Addr))
		})
	}
}

// The LDR form is not decoded, so it never needs slide info. f.SlideInfo is nil here, as in caches
// without slide info (simulator caches); decoding it used to dereference that nil.
func TestObjcMsgSendStubsLDRFormNotDecoded(t *testing.T) {
	fx := loadStubFixture(t)
	f, _, _ := synthCache(t, fx)
	if f.SlideInfo != nil {
		t.Fatal("the synthetic cache has slide info")
	}
	const at, selref, sel = 0x188060000, 0x1f4100008, 0x1f4100100
	words := stub(at, selref, hexAddr(t, fx.ObjcMsgSend))
	words[1] = encLDR(1, 1, selref&0xfff)
	putCode(f, at, words[:]...)
	var ptr [8]byte
	binary.LittleEndian.PutUint64(ptr[:], sel)
	putData(f, selref, ptr[:])
	putData(f, sel, []byte("ldrForm:\x00"))
	noStub(t, f, at)
	if stubs, err := f.GetObjcMsgSendStubs(); err != nil || len(stubs) != len(fx.Stubs) {
		t.Errorf("full scan = (%d stubs, %v), want the %d fixture stubs and no error", len(stubs), err, len(fx.Stubs))
	}
}

// A libobjcMsgSendN image whose __TEXT is in no mapping: the cache is not what this code expects,
// so every entry point fails, including a lookup of a good stub after another image.
func TestObjcMsgSendStubsImageOutsideMappings(t *testing.T) {
	fx := loadStubFixture(t)
	f, caller, _ := synthCache(t, fx)
	f.Images = append(f.Images, &CacheImage{Name: "/usr/lib/objc/libobjcMsgSend1.dylib", cache: f, cuuid: f.UUID,
		CacheImageTextInfo: CacheImageTextInfo{LoadAddress: 0x500000000, TextSegmentSize: 0xf30}})
	failsEverywhere(t, f, caller, hexAddr(t, fx.Stubs[0].Addr), "failed to find mapping for /usr/lib/objc/libobjcMsgSend1.dylib")
}

// _objc_msgSend must come from the image's exports and lie in its __TEXT; without it, the group at
// 0x188050000 that branches to objc_msgSendSuper2 was named _objc_msgSend$<sel>.
func TestObjcMsgSendStubsExport(t *testing.T) {
	fx := loadStubFixture(t)
	for _, tt := range []struct {
		name   string
		change func(*File, *CacheImage)
		want   string
	}{
		{"no export trie", func(_ *File, msgImg *CacheImage) {
			msgImg.ExportsTrieAddr, msgImg.ExportsTrieSize = 0, 0
		}, "failed to find _objc_msgSend in /usr/lib/objc/libobjcMsgSend.dylib"},
		{"export outside __TEXT", func(f *File, msgImg *CacheImage) {
			trie := objcMsgSendTrie(0x2000)
			putData(f, synthTrieAddr, trie)
			msgImg.ExportsTrieSize = uint32(len(trie))
		}, "_objc_msgSend 0x188002000 of /usr/lib/objc/libobjcMsgSend.dylib is outside its __TEXT"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f, caller, msgImg := synthCache(t, fx)
			tt.change(f, msgImg)
			failsEverywhere(t, f, caller, 0x188050000, tt.want)
		})
	}
}

// A stub that decodes but whose selector cannot be read is an error, not a missing stub.
func TestObjcMsgSendStubsBadSelector(t *testing.T) {
	fx := loadStubFixture(t)
	const at, callerAt = 0x188070000, synthCallerBase + 0x100
	for _, tt := range []struct {
		name string
		sel  uint64
		want string
	}{
		{"selector outside every mapping", 0x500000010, "objc_msgSend stub 0x188070000"},
		{"empty selector", 0x1f4100200, "empty selector at 0x1f4100200"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f, _, _ := synthCache(t, fx)
			words := stub(at, tt.sel, hexAddr(t, fx.ObjcMsgSend))
			putCode(f, at, words[:]...)
			putCode(f, callerAt, encBL(callerAt, at))
			caller := &CacheImage{Name: "/usr/lib/libCaller2.dylib", cache: f, cuuid: f.UUID,
				CacheImageTextInfo: CacheImageTextInfo{LoadAddress: callerAt, TextSegmentSize: 4}}
			failsEverywhere(t, f, caller, at, tt.want)
		})
	}
}

// Addresses that cannot start a stub are no stub and no error, including ones where addr+16
// overflows.
func TestObjcMsgSendStubsEdgeAddresses(t *testing.T) {
	fx := loadStubFixture(t)
	f, _, _ := synthCache(t, fx)
	textEnd, mappingEnd := hexAddr(t, fx.TextEnd), hexAddr(t, fx.MappingEnd)
	for _, addr := range []uint64{0, 3, ^uint64(0), ^uint64(0) - 7, ^uint64(0) - 15, textEnd - 4, mappingEnd - 8, mappingEnd, 0x500000000} {
		noStub(t, f, addr)
	}
	if _, ok, err := f.LookupObjcMsgSendStub(hexAddr(t, fx.Stubs[0].Addr) + 2); ok || err != nil {
		t.Errorf("lookup of a misaligned address = (%v, %v), want no stub and no error", ok, err)
	}
}

// On a real cache (DSC=<path>): every stub the full scan finds decodes the same
// way through the single-address lookup, and the middle of a stub is not a stub.
func TestObjcMsgSendStubsRealCache(t *testing.T) {
	f := openImageAddrCache(t)
	regions, err := f.objcMsgSendRegions()
	if err != nil {
		t.Fatal(err)
	}
	if len(regions) == 0 {
		t.Skip("cache has no libobjcMsgSendN images (pre-27), or no room for stubs after them")
	}
	stubs, err := f.GetObjcMsgSendStubs()
	if err != nil {
		t.Fatal(err)
	}
	if len(stubs) == 0 {
		// the iOS 27.0 simulator cache (24A434): 0x190 bytes of zeros after libobjcMsgSend.dylib
		t.Skipf("%d stub ranges after libobjcMsgSendN images, but no selector stubs in them", len(regions))
	}
	checked := 0
	for addr, want := range stubs {
		got, ok, err := f.LookupObjcMsgSendStub(addr)
		if err != nil || !ok || got.Selector != want.Selector || got.Image != want.Image {
			t.Fatalf("lookup %#x = (%+v, %v, %v), want %+v", addr, got, ok, err, want)
		}
		if _, ok, err := f.LookupObjcMsgSendStub(addr + 4); ok || err != nil {
			t.Fatalf("lookup %#x (inside a stub) = (%v, %v), want no stub and no error", addr+4, ok, err)
		}
		if checked++; checked == 2000 {
			break
		}
	}
	t.Logf("%d stubs after %d libobjcMsgSendN images; checked %d", len(stubs), len(regions), checked)
}
