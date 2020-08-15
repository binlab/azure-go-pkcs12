package pkcs12


const (
	TagEndOfContent = 0x00
	TagBoolean = 0x01
	TagInteger = 0x02
	TagBitString = 0x03
	TagOctetString = 0x04
	TagNull = 0x05
	TagOID = 0x06
	TagUTF8String = 0x0C
	TagSequence = 0x10
	TagSet = 0x11
	TagPrintableString = 0x13
	TagUTCTime = 0x17

	ClassUniversal = 0x00
	ClassApplication = 0x40
	ClassContextSpecific = 0x80
	ClassPrivate = 0xC0

	TypeConstructed = 0x20
)

type AsnItem struct {
	tag int
	sz int

	// if raw is non-nil, item is sealed
	raw []byte

	// if content is non-nil, item is primitive type
	content []byte

	// if content is nil, item is a container of these:
	firstChild *AsnItem
	lastChild *AsnItem

	// link for items in container
	next *AsnItem
}

func (a *AsnItem) headersize() int {
	if a.sz < 0 {
		if a.content != nil {
			a.sz = len(a.content)
		} else {
			a.sz = 0
			for c := a.firstChild; c != nil; c = c.next {
				a.sz += c.size()
			}
		}
	}
	if a.sz < 128 {
		return 2
	}
	if a.sz < 256 {
		return 3
	}
	if a.sz < 65536 {
		return 4
	}
	// panic?
	return -1
}

func (a *AsnItem) size() int {
	return a.headersize() + a.sz
}

func (a *AsnItem) write(out []byte) int {
	hsz := a.headersize()
	if hsz < 0 {
		return -1
	}
	out[0] = byte(a.tag)
	if a.sz < 128 {
		out[1] = byte(a.sz)
	} else if a.sz < 256 {
		out[1] = 0x81
		out[2] = byte(a.sz)
	} else if a.sz < 65536 {
		out[1] = 0x82
		out[2] = byte(a.sz >> 8)
		out[3] = byte(a.sz)
	} else {
		// unsupported
		return -1;
	}
	out = out[hsz:]
	if a.content != nil {
		copy(out, a.content)
	} else {
		for c := a.firstChild; c != nil; c = c.next {
			n := c.write(out)
			if n < 0 {
				return -1
			}
			out = out[n:]
		}
	}
	return a.sz + hsz
}

func (a *AsnItem) append(child *AsnItem) *AsnItem {
	// panic if content or >0 size?
	if a.lastChild != nil {
		a.lastChild.next = child;
	} else {
		a.firstChild = child;
	}
	a.lastChild = child;
	return child
}

func AsnNull() *AsnItem {
	return &AsnItem{ tag: TagNull, sz: 0 }
}

func AsnInteger(i int) *AsnItem {
	var data []byte = nil
	if (i < 0) {
		panic("unsupported")
	}
	if (i < 255) {
		data = []byte{ byte(i) }
	} else if i < 65535 {
		data = []byte{ byte(i >> 8), byte(i & 0xff) }
	} else {
		panic("unsupported")
	}
	return &AsnItem{ tag: TagInteger, sz: len(data), content: data }
}

func AsnContainer(_tag int) *AsnItem {
	return &AsnItem{ tag: _tag, sz: -1 }
}

func AsnSequence() *AsnItem {
	return &AsnItem{ tag: TagSequence | TypeConstructed, sz: -1 }
}

func AsnSet() *AsnItem {
	return &AsnItem{ tag: TagSet | TypeConstructed, sz: -1 }
}

func AsnRaw(_tag int, _data []byte) *AsnItem {
	return &AsnItem{ tag: _tag, sz: len(_data), content: _data }
}

func AsnOID(oid []byte) *AsnItem {
	return &AsnItem{ tag: TagOID, sz: len(oid), content: oid }
}

// Context-Specific Container
func AsnCC(n int) *AsnItem {
	return &AsnItem{
		tag: n | ClassContextSpecific | TypeConstructed,
		sz: -1,
	}
}

func AsnCCRaw(n int, data []byte) *AsnItem {
	return &AsnItem{
		tag: n | ClassContextSpecific,
		sz: len(data), content: data,
	}
}

func AsnString(s string) *AsnItem {
	b := []byte(s)
	a := AsnItem{ tag: TagUTF8String, sz: len(b), content: b }
	return &a
}

func AsnOctetStringContainer() *AsnItem {
	return &AsnItem{ tag: TagOctetString, sz: -1 }
}

func AsnOctetString(data []byte) *AsnItem {
	return &AsnItem{ tag: TagOctetString, sz: len(data), content: data }
}


