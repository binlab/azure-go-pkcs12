package pkcs12

import "crypto/rand"

var oid_sha1 = //1 3 14 3 2 26
	[]byte{ 0x2b, 14, 3, 2, 26 }
var oid_pkcs1_rsacrypto = // 1 2 840 113549 1 1 1
	[]byte{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1 }
var oid_pkcs7_data = // 1 2 840 113549 1 7 1
	[]byte{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 7, 1 }
var oid_pkcs7_encrypted = // 1 2 840 113549 1 7 6
	[]byte{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 7, 6 }
var oid_pkcs9_localkeyid = // 1 2 840 113549 1 9 21
	[]byte{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 21 }
var oid_pkcs9_x509cert = // 1 2 840 113549 1 9 22 1
	[]byte{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 9, 22, 1 }
var oid_pkcs12_shrouded_keybag = // 1 2 840 113549 1 12 10 1 2
	[]byte{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 12, 10, 1, 2 }
var oid_pkcs12_certbag = // 1 2 840 113549 1 12 10 1 3
	[]byte{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 12, 10, 1, 3 }
var oid_pkcs12_pbe_sha_3des = // 1 2 840 113549 1 12 1 3
	[]byte{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 12, 1, 3 }
var oid_pkcs12_pbe_sha_rc2 = // 1 2 840 113549 1 12 1 6
	[]byte{ 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 12, 1, 6 }

func getRandomBytes(count int) ([]byte, error) {
	data := make([]byte, count)
	_, err := rand.Read(data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func wrapCert(certificate, keyid []byte) *AsnItem {
	w := AsnSequence()
	w.append(AsnOID(oid_pkcs12_certbag))
	b := w.append(AsnCC(0))
	b = b.append(AsnSequence())
	b.append(AsnOID(oid_pkcs9_x509cert))
	b = b.append(AsnCC(0))
	b = b.append(AsnOctetString(certificate))
	if keyid != nil {
		b = w.append(AsnSet())
		b = b.append(AsnSequence())
		b.append(AsnOID(oid_pkcs9_localkeyid))
		b = b.append(AsnSet())
		b.append(AsnOctetString(keyid))
	}
	return w
}

func createCertBag(certificate, salt, password, keyid []byte, calist [][]byte) (*AsnItem, error) {
	iter := 2048

	payload := AsnSequence()
	payload.append(wrapCert(certificate, keyid))
	for _, cert := range calist {
		payload.append(wrapCert(cert, nil))
	}
	plain := make([]byte, payload.size())
	payload.write(plain)

	encdata, err := pbEncrypt(
		pbewithSHAAnd40BitRC2CBC, plain, salt, password, iter)
	if err != nil {
		return nil, err
	}

	bag := AsnSequence()
	bag.append(AsnOID(oid_pkcs7_encrypted))
	a := bag.append(AsnCC(0))
	a = a.append(AsnSequence())
	a.append(AsnInteger(0))
	a = a.append(AsnSequence())
	a.append(AsnOID(oid_pkcs7_data))
	b := a.append(AsnSequence())
	b.append(AsnOID(oid_pkcs12_pbe_sha_rc2))
	b = b.append(AsnSequence())
	b.append(AsnOctetString(salt))
	b.append(AsnInteger(iter))
	a.append(AsnCCRaw(0, encdata))

	return bag, nil
}

func wrapPrivateKey(privatekey []byte) *AsnItem {
	w := AsnSequence()
	w.append(AsnInteger(0))
	a := w.append(AsnSequence())
	a.append(AsnOID(oid_pkcs1_rsacrypto))
	a.append(AsnNull())
	w.append(AsnOctetString(privatekey))
	return w
}

func createKeyBag(privatekey, salt, password, keyid []byte) (*AsnItem,error) {
	iter := 2048
	payload := wrapPrivateKey(privatekey)
	plain := make([]byte, payload.size())
	payload.write(plain)

	encdata, err := pbEncrypt(
		pbeWithSHAAnd3KeyTripleDESCBC, plain, salt, password, iter)
	if err != nil {
		return nil, err
	}

	bag := AsnSequence()
	bag.append(AsnOID(oid_pkcs7_data))
	a := bag.append(AsnCC(0))
	a = a.append(AsnOctetStringContainer())
	a = a.append(AsnSequence())
	a = a.append(AsnSequence())
	a.append(AsnOID(oid_pkcs12_shrouded_keybag))
	b := a.append(AsnCC(0))
	b = b.append(AsnSequence())
	c := b.append(AsnSequence())
	c.append(AsnOID(oid_pkcs12_pbe_sha_3des))
	c = c.append(AsnSequence())
	c.append(AsnOctetString(salt))
	c.append(AsnInteger(iter))
	b.append(AsnOctetString(encdata))
	a = a.append(AsnSet())
	a = a.append(AsnSequence())
	a.append(AsnOID(oid_pkcs9_localkeyid))
	a = a.append(AsnSet())
	a.append(AsnOctetString(keyid))

	return bag, nil
}

func CreateEtc(certificate, privatekey, password []byte, calist [][]byte,
		keyid, certsalt, pkeysalt, macsalt []byte) ([]byte, error) {
	password, err := bmpString(password)
	if err != nil {
		return nil, err
	}

	bags := AsnSequence()

	bag, err := createCertBag(certificate, certsalt, password, keyid, calist)
	if err != nil {
		return nil, err
	}
	bags.append(bag)

	bag, err = createKeyBag(privatekey, pkeysalt, password, keyid)
	if err != nil {
		return nil, err
	}
	bags.append(bag)

	bagdata := make([]byte, bags.size())
	bags.write(bagdata)

	mac, err := generateMacSha1(bagdata, macsalt, password, 2048)
	if err != nil {
		return nil, err
	}

	p12 := AsnSequence()
	p12.append(AsnInteger(3))
	a := p12.append(AsnSequence())
	a.append(AsnOID(oid_pkcs7_data))
	a = a.append(AsnCC(0))
	a.append(AsnOctetString(bagdata))

	a = p12.append(AsnSequence())
	b := a.append(AsnSequence())
	c := b.append(AsnSequence())
	c.append(AsnOID(oid_sha1))
	c.append(AsnNull())
	b.append(AsnOctetString(mac))
	a.append(AsnOctetString(macsalt))
	a.append(AsnInteger(2048))

	data := make([]byte, p12.size())
	p12.write(data)

	return data, nil
}


func Create(certificate, privatekey, password []byte, calist [][]byte) ([]byte, error) {
	keyid, err := getRandomBytes(20)
	if err != nil {
		return nil, err
	}
	macsalt, err := getRandomBytes(8)
	if err != nil {
		return nil, err
	}
	pkeysalt, err := getRandomBytes(8)
	if err != nil {
		return nil, err
	}
	certsalt, err := getRandomBytes(8)
	if err != nil {
		return nil, err
	}
	return CreateEtc(
		certificate, privatekey, password, calist,
		keyid, certsalt, pkeysalt, macsalt)
}
