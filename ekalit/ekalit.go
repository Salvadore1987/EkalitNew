package ekalit

import (
	"syscall"
	"unsafe"
	"fmt"
	"encoding/hex"
	"runtime"
)

var (
	libesigner *syscall.DLL
)

const (
	ALG_UZDST2 = 1
	ALG_UZDST1 = 0
)

type Ekalit struct {
	ekalitPtr uintptr
}

type Hash struct {
	hashPtr uintptr
}

type Signature struct {
	signaturePtr uintptr
}

//--------------------------------------------------------------- EKD Block Begin ---------------------------------------------------------------------------

/************************************************************************************************
 *	Функция создает новый объект ЭЦП.                                                          *
 ************************************************************************************************/
func NewEkalit() *Ekalit {
	if runtime.GOARCH == "amd64" {
		libesigner = syscall.MustLoadDLL("ekalit/64/libesigner.dll")
	} else {
		libesigner = syscall.MustLoadDLL("ekalit/32/libesigner.dll")
	}
	ekdNew := libesigner.MustFindProc("EKDNew")
	r, _, _ := ekdNew.Call()
	ekalit := new(Ekalit)
	ekalit.ekalitPtr = r
	return ekalit
}

/**************************************************************************************************
 *	Метод возвращает указатель на объект Ekalit.                                                 *
 **************************************************************************************************/
func (e *Ekalit) GetEkalitPtr() uintptr {
	return e.ekalitPtr
}

/*************************************************************************************************
 *	Функция проверяет подсоединено ли устройство к USB порту,                                   *
 *	в случае успеха возвращает true, иначе false.                                               *
 *************************************************************************************************/
func (e *Ekalit) IsConnected() (result bool) {
	isConnected := libesigner.MustFindProc("EKDIsConnected")
	r, _, _ := isConnected.Call(e.ekalitPtr)
	if r > 0 {
		return true
	} else {
		return false
	}
}

/*************************************************************************************************
 *	Функция закрывает объект ЭЦП.                                                               *
 *************************************************************************************************/
func (e *Ekalit) EkalitFree()  {
	ekdFree := libesigner.MustFindProc("EKDFree")
	_, _, _ = ekdFree.Call(e.ekalitPtr)
}

/*************************************************************************************************
 *	Функция возвращает код-ошибки в случае неудачной операции.                                  *
 *************************************************************************************************/
func (e *Ekalit) EkalitGetErrorCode() uint32 {
	ekdGetErrorCode := libesigner.MustFindProc("EKDGetErrorCode")
	r, _, _ := ekdGetErrorCode.Call(e.ekalitPtr)
	return uint32(r)
}

/****************************************************************************************************
 *	Функция возвращает текст ошибки при неудачной операции.                                        *
 ****************************************************************************************************/
func (e *Ekalit) EkalitGetError() string {
	ekdError := libesigner.MustFindProc("EKDGetError")
	r, _, _ := ekdError.Call(e.ekalitPtr)
	return BytePtrToString((*byte)(unsafe.Pointer(r)))
}

/************************************************************************************************
 *	Функция считывает сертификат с ЭЦП.                                                        *
 ************************************************************************************************/
func (e *Ekalit) ReadCertificate(password string) (result string) {
	pasPtr, err := syscall.BytePtrFromString(password)
	if err != nil {
		panic(err)
	}
	readCertificate := libesigner.MustFindProc("EKDReadCertificate")
	r, _, _ := readCertificate.Call(e.ekalitPtr, uintptr(unsafe.Pointer(pasPtr)))
	return BytePtrToString((*byte)(unsafe.Pointer(r)))
}

/***********************************************************************************************
 *	Функция возвращает серийный номер устройства.                                             *
 ***********************************************************************************************/
func (e *Ekalit) EkalitGetUID() string {
	ekdGetUID := libesigner.MustFindProc("EKDGetUID")
	r, _, _ := ekdGetUID.Call(e.ekalitPtr)
	return UPointerToString(r)
}

//--------------------------------------------------------------- EKD Block End -----------------------------------------------------------------------------

//--------------------------------------------------------------- Hash Block Begin ---------------------------------------------------------------------------

/*************************************************************************************************
 *	Функция создает объект типа Hash и возвращаетуказатель на него.                             *
 *************************************************************************************************/
func HashNew() *Hash {
	hashNew := libesigner.MustFindProc("HashNew")
	r, _, _ := hashNew.Call()
	return &Hash{r}
}

/***************************************************************************************************
 *	Функция проверяет завершилась ли операции формирования хеша или нет.                          *
 ***************************************************************************************************/
func (h *Hash) Finish() (*[]byte) {
	result := new([]byte)
	hashFinish := libesigner.MustFindProc("HashFinish")
	_, _, _ = hashFinish.Call(h.hashPtr, uintptr(unsafe.Pointer(result)))
	return result
}

/******************************************************************************************************
 *	Функция проберяет был ли сброшен хеш-код.                                                        *
 ******************************************************************************************************/
func (h *Hash) Reset() bool {
	hashReset := libesigner.MustFindProc("HashReset")
	r, _, _ := hashReset.Call(h.hashPtr)
	if r > 0 {
		return true
	} else {
		return false
	}
}

/******************************************************************************************************
 *	Функция проберяет был ли обновлен хеш-код.                                                       *
 ******************************************************************************************************/
func (h *Hash) Update(pHash uintptr, str string) bool {
	lenght := len(str)
	hashUpdate := libesigner.MustFindProc("HashUpdate")
	p, err := syscall.UTF16PtrFromString(str)
	if err != nil {
		panic("error")
	}
	r, _, _ := hashUpdate.Call(h.hashPtr, uintptr(unsafe.Pointer(p)), uintptr(lenght))
	if r > 0 {
		return true
	} else {
		return false
	}
}

/*******************************************************************************************************
 *	Функция удаляет объект Hash.                                                                      *
 *******************************************************************************************************/
func (h *Hash) HashFree(pHash uintptr)  {
	hashFree := libesigner.MustFindProc("HashFree")
	_, _, _ = hashFree.Call(h.hashPtr)
}

/*********************************************************************************************************
 *	Функция принимает массив байт [0..31] и формирует хеш-строку внутри библиотеки                      *
 *	и возвращает указатель на эту строку. Для последующего использования.                               *
 *********************************************************************************************************/
func (h *Hash) OfBytes(pData uintptr, len int) uintptr {
	hashOfBytes := libesigner.MustFindProc("HashOfBytes")
	r, _, _ := hashOfBytes.Call(h.hashPtr, pData, uintptr(len))
	return r
}

/*********************************************************************************************************
 *	Функция принимает строку и формирует из нее хеш-строку внутри библиотеки                            *
 *	и возвращает указатель на эту строку. Для последующего использования.                               *
 *********************************************************************************************************/
func (h *Hash) OfString(pStr string) [32]byte {
	result := &[32]byte{}
	hashOfString := libesigner.MustFindProc("HashOfString")
	p, err := syscall.BytePtrFromString(pStr)
	if err != nil {
		panic("error")
	}
	_, _, _ = hashOfString.Call(h.hashPtr, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(result)))
	return *result
}

func (h *Hash) BytesToString(b [32]byte) string {
	return hex.EncodeToString(b[:])
}

//--------------------------------------------------------------- Hash Block End -----------------------------------------------------------------------------

//--------------------------------------------------------------- Signature Block Begin -----------------------------------------------------------------------

func SignatureNew(algConst int) *Signature {
	signatureNew := libesigner.MustFindProc("SignatureNew")
	r, _, _ := signatureNew.Call(uintptr(algConst))
	return &Signature{r}
}

func (s *Signature) SignatureFree()  {
	signatureFree := libesigner.MustFindProc("SignatureFree")
	_, _, _ = signatureFree.Call(s.signaturePtr)
}

func (s *Signature) SignatureGenerate(hash [32]byte, pEkt uintptr, password string) bool {
	signatureGenerate := libesigner.MustFindProc("SignatureGenerate2")
	p, err := syscall.UTF16PtrFromString(password)
	if err != nil {
		fmt.Println(err)
	}
	r, _, err := signatureGenerate.Call(s.signaturePtr, uintptr(unsafe.Pointer(&hash[0])), 32, pEkt, uintptr(unsafe.Pointer(p)))
	fmt.Println(err)
	if r > 0 {
		return true
	} else {
		return false
	}
}

func (s *Signature) SignatureGetBytes() string {
	length := signatureGetBytesLength(s.signaturePtr)
	fmt.Printf("Length is %v\n", length)
	var result = make([]byte, length)
	signatureGetBytes := libesigner.MustFindProc("SignatureGetBytes")
	_, _, _ = signatureGetBytes.Call(s.signaturePtr, *(*uintptr)(unsafe.Pointer(&result[0])))
	return s.BytesToString(result)
}

func (s *Signature) BytesToString(b []byte) string {
	return hex.EncodeToString(b[:])
}

func signatureGetBytesLength(pSignature uintptr) int {
	signatureGetBytesLength := libesigner.MustFindProc("SignatureGetBytesLength")
	r1, _, _ := signatureGetBytesLength.Call(pSignature)
	return int(r1)
}

func (s *Signature) SignatureGetError() string {
	signatureGetBytesLength := libesigner.MustFindProc("SignatureGetError")
	r1, _, err := signatureGetBytesLength.Call(s.signaturePtr)
	fmt.Println(err)
	str := BytePtrToString((*byte)(unsafe.Pointer(r1)))
	return str
}

//--------------------------------------------------------------- Signature Block End -----------------------------------------------------------------------






/*************************************************************************************************
 *	Функция переводит одно-байтовый указатель в строку и возвращает полученный результат.       *
 *************************************************************************************************/
func BytePtrToString(s *byte) string {
	if s != nil {
		bs := make([]byte, 0, 256)
		for p := uintptr(unsafe.Pointer(s)); ; p += 1 {
			b := *(*byte)(unsafe.Pointer(p))
			if b == 0 {
				return string(bs)
			}
			bs = append(bs, b)
		}
	}
	return ""
}

/*************************************************************************************************
 *	Функция переводит указатель в строку и возвращает полученный результат.                     *
 *************************************************************************************************/
func UPointerToString(ptr uintptr) string {
	if ptr != 0 {
		bs := make([]byte, 0, 255)
		for p := uintptr(unsafe.Pointer(ptr)); ; p += 1 {
			b := *(*byte)(unsafe.Pointer(p))
			if b == 0 {
				return string(bs)
			}
			bs = append(bs, b)
		}
	}
	return ""
}