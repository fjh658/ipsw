package dyld

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"slices"

	"github.com/blacktop/go-macho/types"
)

// iOS/macOS 27 caches move ObjC selector stubs out of each image's __objc_stubs
// section. Every caller branches (B/BL, ±128 MB) to a stub placed right after the
// __TEXT of the nearest copy of objc_msgSend, /usr/lib/objc/libobjcMsgSend.dylib
// through libobjcMsgSendN.dylib. Those images declare only the few KB of
// objc_msgSend itself, so the stubs are outside every LC_SEGMENT and every image
// text-info entry, and address lookups miss them. Each stub is 16 bytes:
//
//	adrp x1, sel@PAGE
//	add  x1, x1, sel@PAGEOFF   ; or ldr x1, [x1, selref@PAGEOFF]
//	b    _objc_msgSend         ; the copy in the same image's __TEXT
//	brk  #1
//
// Only the ADD form is decoded. The LDR form would need the slid selector
// reference, and no 27 cache seen so far has one (macOS 26A434: 0 of 1,550,319
// stubs), so such a stub stays unnamed, as before this file existed.
//
// Errors: a cache without libobjcMsgSendN images, or with no room for a stub
// after one, has no stubs; that is not an error. A libobjcMsgSendN image whose
// __TEXT is in no mapping or that does not export _objc_msgSend inside its
// __TEXT, or a stub whose selector cannot be read, is an error: every function
// here returns it instead of reporting fewer stubs.

var objcMsgSendImageRE = regexp.MustCompile(`^/usr/lib/objc/libobjcMsgSend[0-9]*\.dylib$`)

const (
	ObjcMsgSendStubSize = 16 // bytes per selector stub
	arm64InsnBrk1       = 0xd4200020
)

// ObjcMsgSendStub is one selector stub found after a libobjcMsgSendN image.
type ObjcMsgSendStub struct {
	Image    *CacheImage
	Selector string
}

// SymbolName is the name the address-to-symbol table uses for ObjC stubs
// (same form as the per-image __objc_stubs entries).
func (s ObjcMsgSendStub) SymbolName() string {
	return fmt.Sprintf("j__objc_msgSend(x0, \"%s\")", s.Selector)
}

// LinkerName is the linker's name for the stub, as in `_objc_msgSend$<sel>`.
func (s ObjcMsgSendStub) LinkerName() string {
	return "_objc_msgSend$" + s.Selector
}

// objcMsgSendRegion is the stub range after one libobjcMsgSendN image.
type objcMsgSendRegion struct {
	image   *CacheImage
	msgSend uint64 // the stub's B must land here: the image's exported _objc_msgSend
	textEnd uint64 // stubs start at the end of __TEXT
	end     uint64 // end of the stub range (next image or end of the mapping)
}

func signExtend(v uint64, bits uint) int64 {
	shift := 64 - bits
	return int64(v<<shift) >> shift
}

// decodeObjcMsgSendStub decodes the stub at pc; its B must land on msgSend.
// It returns the selector string address (ADD form only, see the top of the file).
func decodeObjcMsgSendStub(insns [4]uint32, pc, msgSend uint64) (sel uint64, ok bool) {
	adrp, add, b, brk := insns[0], insns[1], insns[2], insns[3]
	if adrp&0x9f00001f != 0x90000001 || b&0xfc000000 != 0x14000000 || brk != arm64InsnBrk1 { // ADRP x1, B, BRK #1
		return 0, false
	}
	if add&0xff8003ff != 0x91000021 { // ADD x1, x1, #imm{, LSL #12}
		return 0, false
	}
	if target := uint64(int64(pc+8) + signExtend(uint64(b&0x03ffffff), 26)*4); target != msgSend {
		return 0, false
	}
	immlo := uint64(adrp>>29) & 0x3
	immhi := uint64(adrp>>5) & 0x7ffff
	page := uint64(int64(pc&^0xfff) + signExtend(immhi<<2|immlo, 21)<<12)
	imm12 := uint64(add>>10) & 0xfff
	if add&(1<<22) != 0 {
		imm12 <<= 12
	}
	return page + imm12, true
}

// objcMsgSendRegions finds the stub range after every libobjcMsgSendN image.
// It only looks at image and mapping tables; no stub bytes are read. The result,
// including an error, is computed once and returned by every later call.
func (f *File) objcMsgSendRegions() ([]objcMsgSendRegion, error) {
	f.objcStubRegionsOnce.Do(func() {
		f.objcStubRegions, f.objcStubRegionsErr = f.findObjcMsgSendRegions()
	})
	return f.objcStubRegions, f.objcStubRegionsErr
}

func (f *File) findObjcMsgSendRegions() ([]objcMsgSendRegion, error) {
	loads := make([]uint64, 0, len(f.Images))
	for _, img := range f.Images {
		loads = append(loads, img.LoadAddress)
	}
	slices.Sort(loads)
	var regions []objcMsgSendRegion
	for _, img := range f.Images {
		if !objcMsgSendImageRE.MatchString(img.Name) || img.TextSegmentSize == 0 {
			continue
		}
		textEnd := img.LoadAddress + uint64(img.TextSegmentSize)
		_, mapping, err := f.GetMappingForVMAddress(textEnd - 1)
		if err != nil {
			return nil, fmt.Errorf("failed to find mapping for %s: %v", img.Name, err)
		}
		end := mapping.Address + mapping.Size
		if i, _ := slices.BinarySearch(loads, textEnd); i < len(loads) {
			end = min(end, loads[i]) // the next image
		}
		if end-textEnd < ObjcMsgSendStubSize {
			continue // the next image starts right after __TEXT (or the mapping ends there): no stubs
		}
		// Every 26A434 stub branches to the image's _objc_msgSend (image+0x800); the
		// same __TEXT also holds objc_msgSendSuper2, objc_msgLookup, ... Accept only
		// _objc_msgSend so a stub to another entry point is not named objc_msgSend$.
		exp, err := img.GetExport("_objc_msgSend")
		if err != nil {
			return nil, fmt.Errorf("failed to find _objc_msgSend in %s: %v", img.Name, err)
		}
		if exp.Address < img.LoadAddress || exp.Address >= textEnd {
			return nil, fmt.Errorf("_objc_msgSend %#x of %s is outside its __TEXT [%#x, %#x)", exp.Address, img.Name, img.LoadAddress, textEnd)
		}
		regions = append(regions, objcMsgSendRegion{image: img, msgSend: exp.Address, textEnd: textEnd, end: end})
	}
	return regions, nil
}

// selectorName returns the selector string at addr, memoized: the same selector
// has a stub in many of the libobjcMsgSendN copies.
func (f *File) selectorName(addr uint64) (string, error) {
	f.selNamesMu.Lock()
	defer f.selNamesMu.Unlock()
	if name, ok := f.selNames[addr]; ok {
		return name, nil
	}
	name, err := f.GetCString(addr)
	if err != nil {
		return "", fmt.Errorf("failed to read selector at %#x: %v", addr, err)
	}
	if name == "" {
		return "", fmt.Errorf("empty selector at %#x", addr)
	}
	if f.selNames == nil {
		f.selNames = make(map[uint64]string)
	}
	f.selNames[addr] = name
	return name, nil
}

func (f *File) readInsns(uuid types.UUID, off uint64, n int) ([]uint32, error) {
	dat, err := f.ReadBytesForUUID(uuid, int64(off), uint64(n*4))
	if err != nil {
		return nil, err
	}
	insns := make([]uint32, n)
	for i := range insns {
		insns[i] = binary.LittleEndian.Uint32(dat[i*4:])
	}
	return insns, nil
}

// LookupObjcMsgSendStub returns the selector stub at addr, if addr is the start
// of one. It decodes only that stub. ok is false when addr is not a stub; err is
// set when the stub ranges cannot be found or a stub at addr cannot be read.
func (f *File) LookupObjcMsgSendStub(addr uint64) (ObjcMsgSendStub, bool, error) {
	regions, err := f.objcMsgSendRegions()
	if err != nil {
		return ObjcMsgSendStub{}, false, err
	}
	for _, r := range regions {
		if addr < r.textEnd || addr >= r.end || r.end-addr < ObjcMsgSendStubSize || addr%4 != 0 {
			continue
		}
		uuid, off, err := f.GetOffset(addr)
		if err != nil {
			return ObjcMsgSendStub{}, false, err
		}
		insns, err := f.readInsns(uuid, off, 4)
		if err != nil {
			return ObjcMsgSendStub{}, false, fmt.Errorf("failed to read objc_msgSend stub %#x: %v", addr, err)
		}
		sel, ok := decodeObjcMsgSendStub([4]uint32(insns), addr, r.msgSend)
		if !ok {
			return ObjcMsgSendStub{}, false, nil
		}
		name, err := f.selectorName(sel)
		if err != nil {
			return ObjcMsgSendStub{}, false, fmt.Errorf("objc_msgSend stub %#x: %v", addr, err)
		}
		return ObjcMsgSendStub{Image: r.image, Selector: name}, true, nil
	}
	return ObjcMsgSendStub{}, false, nil
}

// GetObjcMsgSendStubs decodes every selector stub after every libobjcMsgSendN
// image, keyed by stub address. Caches without those images return an empty map.
func (f *File) GetObjcMsgSendStubs() (map[uint64]ObjcMsgSendStub, error) {
	regions, err := f.objcMsgSendRegions()
	if err != nil {
		return nil, err
	}
	stubs := make(map[uint64]ObjcMsgSendStub)
	for _, r := range regions {
		uuid, off, err := f.GetOffset(r.textEnd)
		if err != nil {
			return nil, fmt.Errorf("failed to get offset of %s stubs: %v", r.image.Name, err)
		}
		insns, err := f.readInsns(uuid, off, int((r.end-r.textEnd)/4))
		if err != nil {
			return nil, fmt.Errorf("failed to read %s stubs: %v", r.image.Name, err)
		}
		// Step one instruction at a time until a stub matches, then a whole stub:
		// the range starts at the unaligned end of __TEXT and ends in zero padding.
		for i := 0; i+4 <= len(insns); {
			pc := r.textEnd + uint64(i)*4
			sel, ok := decodeObjcMsgSendStub([4]uint32(insns[i:i+4]), pc, r.msgSend)
			if !ok {
				i++
				continue
			}
			name, err := f.selectorName(sel)
			if err != nil {
				return nil, fmt.Errorf("objc_msgSend stub %#x after %s: %v", pc, r.image.Name, err)
			}
			stubs[pc] = ObjcMsgSendStub{Image: r.image, Selector: name}
			i += ObjcMsgSendStubSize / 4
		}
	}
	return stubs, nil
}

// GetObjcMsgSendStubsCalledBy returns the selector stubs the image's __TEXT
// branches to (B/BL), keyed by stub address.
func (f *File) GetObjcMsgSendStubsCalledBy(img *CacheImage) (map[uint64]ObjcMsgSendStub, error) {
	stubs := make(map[uint64]ObjcMsgSendStub)
	regions, err := f.objcMsgSendRegions()
	if err != nil {
		return nil, err
	}
	if len(regions) == 0 || img.TextSegmentSize == 0 {
		return stubs, nil
	}
	uuid, off, err := f.GetOffset(img.LoadAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to get offset of %s __TEXT: %v", img.Name, err)
	}
	insns, err := f.readInsns(uuid, off, int(img.TextSegmentSize/4))
	if err != nil {
		return nil, fmt.Errorf("failed to read %s __TEXT: %v", img.Name, err)
	}
	inRegion := func(addr uint64) bool {
		for _, r := range regions {
			if addr >= r.textEnd && addr < r.end {
				return true
			}
		}
		return false
	}
	seen := make(map[uint64]bool)
	for i, insn := range insns {
		if insn&0x7c000000 != 0x14000000 { // B or BL
			continue
		}
		pc := img.LoadAddress + uint64(i)*4
		target := uint64(int64(pc) + signExtend(uint64(insn&0x03ffffff), 26)*4)
		if seen[target] || !inRegion(target) {
			continue
		}
		seen[target] = true
		s, ok, err := f.LookupObjcMsgSendStub(target)
		if err != nil {
			return nil, err
		}
		if ok {
			stubs[target] = s
		}
	}
	return stubs, nil
}

// ObjcMsgSendStubContaining returns the start of the selector stub that addr
// falls in, and the stub. A misaligned start cannot pass the four instruction
// checks, so at most one of the four candidates matches.
func (f *File) ObjcMsgSendStubContaining(addr uint64) (uint64, ObjcMsgSendStub, bool, error) {
	base := addr &^ 3
	for k := uint64(0); k < ObjcMsgSendStubSize/4 && k*4 <= base; k++ {
		start := base - k*4
		s, ok, err := f.LookupObjcMsgSendStub(start)
		if err != nil {
			return 0, ObjcMsgSendStub{}, false, err
		}
		if ok && addr < start+ObjcMsgSendStubSize {
			return start, s, true, nil
		}
	}
	return 0, ObjcMsgSendStub{}, false, nil
}
